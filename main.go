package main

import (
  "database/sql"
  "errors"
  "flag"
  "fmt"
  "io"
  "log"
  "net/http"
  "os"
  "path/filepath"
  "runtime"
  "strings"
  "sync"

  sqlite3 "github.com/mattn/go-sqlite3"
  webs "golang.org/x/net/websocket"
  "golang.org/x/crypto/bcrypt"
)

func main() {
  addr := flag.String("addr", "127.0.0.1:8000", "Address to run on")
  flag.Parse()

  logger := log.New(os.Stderr, "", 0)

  _, thisFile, _, _ := runtime.Caller(0)
  thisDir := filepath.Dir(thisFile)

  // Get the log file
  logFile, err := os.OpenFile(
    filepath.Join(thisDir, "simplist.log"),
    os.O_CREATE|os.O_APPEND|os.O_WRONLY,
    0644,
  )
  if err != nil {
    log.Fatal("error opening log file", err)
  }
  logger.SetOutput(logFile)

  db, err := sql.Open("sqlite3", filepath.Join(thisDir, "simplist.db"))
  if err != nil {
    logger.Fatal("error opening db: ", err)
  }

  indexPath := filepath.Join(thisDir, "index.html")

  s := &server{logger: logger, db: db, indexPath: indexPath}
  srvr := http.Server{
    Addr: *addr,
    Handler: s,
    ErrorLog: s.logger,
  }
  log.Fatal(srvr.ListenAndServe())
}

type server struct {
  logger *log.Logger
  db *sql.DB
  indexPath string

  activeUsers sync.Map
}

func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
  path := strings.TrimPrefix(r.URL.Path, "/")
  switch path {
  case "ws":
    webs.Handler(s.handleWs).ServeHTTP(w, r)
  default:
    s.serveHome(w, r)
  }
}

func (s *server) serveHome(w http.ResponseWriter, r *http.Request) {
  http.ServeFile(w, r, s.indexPath)
}

func (s *server) handleWs(ws *webs.Conn) {
  defer ws.Close()
  logFmtPrefix := fmt.Sprintf("[%s|]", ws.RemoteAddr())
  logFunc := func(format string, args ...any) {
    s.logger.Printf(logFmtPrefix+format, args...)
  }

  msg := Message{}
  for {
    if err := webs.JSON.Receive(ws, &msg); err != nil {
      ws.Write([]byte("bad message, closing"))
      return
    }
    switch msg.Action {
    case ActionRegister:
      if msg.User.Email == "" {
        webs.JSON.Send(ws, msg.errResp("invalid email or password"))
        continue
      }
      passwordHashBytes, err := bcrypt.GenerateFromPassword(
        msg.User.Password, bcrypt.DefaultCost,
      )
      if err != nil {
        webs.JSON.Send(ws, msg.errResp("bad email or password"))
      }
      passwordHash := string(passwordHashBytes)
      _, err = s.db.Exec(`INSERT INTO users VALUES (?,?)`, msg.User.Email, passwordHash)
      if err != nil {
        if errors.Is(err, sqlite3.ErrorConstraintUnique); err != nil {
          webs.JSON.Send(ws, msg.errResp("user already exists"))
        } else {
          logFunc("error creating user (email: %s): %v", msg.User.Email, err)
          webs.JSON.Send(ws, msg.errResp("internal server error"))
        }
        continue
      }
      webs.JSON.Send(ws, msg.okResp())
    case ActionLogin:
      row := s.db.QueryRow(`SELECT password_hash FROM users WHERE email=?`, msg.User.Email)
      passwordHash := ""
      if err := row.Scan(&passwordHash); err != nil {
        if errors.Is(err, sql.ErrNoRows) {
          ws.Write([]byte(""))
        } else {
          logFunc("error getting user (email: %s) data: %v", msg.User.Email, err)
          ws.Write([]byte("internal server error"))
        }
        continue
      }
      if bcrypt.CompareHashAndPassword([]byte(passwordHash), msg.User.Password) != nil {
        webs.JSON.Send(ws, msg.errResp("invalid password"))
        continue
      }
      webs.JSON.Send(ws, msg.okResp())
    default:
      webs.JSON.Send(ws, msg.errResp("invalid action"))
      continue
    }
    break
  }
  email := msg.User.Email
  iConnsMap, _ := s.activeUsers.LoadOrStore(email, sync.Map{})
  connsMap := iConnsMap.(sync.Map)
  connsMap.Store(ws.RemoteAddr().String(), ws)
  defer connsMap.Delete(ws.RemoteAddr().String())

  logFmtPrefix = fmt.Sprintf("[%s|%s]", ws.RemoteAddr(), email)
  logFunc = func(format string, args ...any) {
    s.logger.Printf(logFmtPrefix+format, args...)
  }

  if msg.Action == ActionLogin {
    rows, err := s.db.Query(`SELECT * FROM items WHERE email=?`, email)
    if err != nil {
      logFunc("error getting items: %v", err)
    }
    items, respErr := []Item{}, ""
    for rows.Next() {
      item := Item{}
      if err := rows.Scan(&item.Id, &item.What, &item.CompletedAt); err != nil {
        logFunc("error querying row: %v", err)
        respErr = "internal server error"
      }
      items = append(items, item)
    }
    rows.Close()
    resp := Response{
      MsgId: -1,
      Action: ActionGet,
      Items: items,
      Error: respErr,
    }
    webs.JSON.Send(ws, resp)
  }
  
  broadcast := func(resp Response) {
    connsMap.Range(func(_, iConn any) bool {
      webs.JSON.Send(iConn.(*webs.Conn), resp)
      return true
    })
  }

  for {
    if err := webs.JSON.Receive(ws, &msg); err != nil {
      if !errors.Is(err, io.EOF) {
        // TODO: Check error
        //logFunc("error receiving or decoding message: %v", err)
        webs.JSON.Send(ws, msg.errResp("bad message"))
        continue
      }
      return
    }
    switch msg.Action {
    case ActionInsert:
      res, err := s.db.Exec(
        `INSERT INTO items(what, completed_at) VALUES (?,?)`,
      )
      if err != nil {
        logFunc("error inserting item: %v", err)
        webs.JSON.Send(ws, msg.errResp("internal server error"))
        continue
      }
      id, err := res.LastInsertId()
      if err != nil {
        logFunc("error gettintg last insert id: %v", err)
      }
      msg.Item.Id = id
      broadcast(msg.itemResp())
    case ActionUpdate:
      _, err := s.db.Exec(
        `UPDATE items SET(what, completed_at) SET what=?, completedAt=? WHERE id=?`,
        msg.Item.What, msg.Item.CompletedAt, msg.Item.Id,
      )
      if err != nil {
        logFunc("error inserting item: %v", err)
        webs.JSON.Send(ws, msg.errResp("internal server error"))
        continue
      }
      webs.JSON.Send(ws, msg.okResp())
      broadcast(msg.itemResp())
    case ActionGet:
      rows, err := s.db.Query(`SELECT * FROM items WHERE email=?`, email)
      if err != nil {
        logFunc("error querying items: %v", err)
        webs.JSON.Send(ws, msg.errResp("internal server error"))
      }
      var items []Item
      respErr := ""
      for rows.Next() {
        item := Item{}
        if err := rows.Scan(&item.Id, &item.What, &item.CompletedAt); err != nil {
          logFunc("error querying row: %v", err)
          respErr = "internal server error"
        }
        items = append(items, item)
      }
      resp := msg.errResp(respErr)
      resp.Items = items
      webs.JSON.Send(ws, resp)
    default:
      webs.JSON.Send(ws, msg.errResp("invalid action"))
    }
  }
}

type User struct {
  Email string `json:"email"`
  Password string `json:"password"`
}

type Item struct {
  Id int64 `json:"id"`
  What string `json:"what"`
  CompletedAt int64 `json:"completedAt"`
}
/*
_, err := s.db.Exec(
  `REPLACE INTO items (what, completed_at) VALUES (?,?)`,
  msg.Item.What, msg.Item.CompletedAt,
)
if err != nil {
  logFunc("error replacing item (%v): %v", item, err)
}
*/

type Action string

const (
  ActionUnknown Action = ""
  ActionRegister Action = "register"
  ActionLogin Action = "login"
  ActionGet Action = "get"
  ActionInsert Action = "insert"
  ActionUpdate Action = "update"
  ActionDelete Action = "delete"
)

type Message struct {
  Id int64 `json:"id"`
  Action Action `json:"action"`
  User User `json:"user,omitempty"`
  Item Item `json:"item,omitempty"`
}

func (msg Message) okResp() Response {
  return Response{
    MsgId: msg.Id,
    Action: msg.Action,
  }
}

func (msg Message) itemResp() Response {
  return Response{
    MsgId: -1,
    Action: msg.Action,
    Items: []Item{msg.Item},
  }
}

func (msg Message) itemsResp(items []Item) Response {
  return Response{
    MsgId: -1,
    Action: msg.Action,
    Items: items,
  }
}

func (msg Message) errResp(err string) Response {
  return Response{
    MsgId: msg.Id,
    Action: msg.Action,
    Error: err,
  }
}

type Response struct {
  MsgId int64 `json:"msgId"`
  Action Action `json:"action"`
  Items []Item `json:"items,omitempty"`
  Error string `json:"error,omitempty"`
}
