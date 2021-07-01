const express = require('express');
const app = express();
var cookieParser = require('cookie-parser');
app.use(cookieParser());
const router = express.Router();
const path = require('path')
const cors = require('cors');
app.use(cors({
  origin: function(origin, callback){
    return callback(null, true);
  },
  credentials: true, // <= Accept credentials (cookies) sent by the client
}))
const Database = require("@replit/database");
const db = new Database()
const bcrypt = require('bcrypt')
const WebSocketServer = require('websocket').server;
const url = require('url');
const cloudinary = require('cloudinary').v2
cloudinary.config({ 
  cloud_name: 'doooij2qr', 
  api_key: '525257699528752', 
  api_secret: process.env['cloudinary_api_secret']
});

/*var id = 0xf
function generateId(){
  id += Math.floor(Math.random() * 10)
  return id.toString(64)
}*/
//var genid = 0
function generateId(){
  //genid ++
  //return genid
  return Date.now()
}

router.get('/', function(req, res){
  res.sendFile(path.join(__dirname, "/info.html"));
});

router.get('/test', function(req, res){
  res.send("test")
});

function getPostData(req){
  return new Promise(function(resolve){
    let body = '';
    req.on('data', chunk => {
      body += chunk.toString(); // convert Buffer to string
    });
    req.on('end', () => {
      body = JSON.parse(body)
      req.body = body
      resolve(body)
    });
  })
}
function getPostText(req){
  return new Promise(function(resolve){
    let body = '';
    req.on('data', chunk => {
      body += chunk.toString(); // convert Buffer to string
    });
    req.on('end', () => {
      req.body = body
      resolve(body)
    });
  })
}
//cookies to see if you logged in
function setUser(sid, res){
  return res.cookie("sid", sid, {
    maxAge:4000000000,
    path: "/",
    domain: ".thingmaker.repl.co"
  });
}
function logout(request, res){
  return new Promise(async (resolve, reject) => {
    var sid = request.cookies.sid
    /*res.cookie("sid", "", {
      maxAge:0,
      path: "/",
      domain: ".thingmaker.repl.co"
    });*/
    res.clearCookie("sid",{
      maxAge:0,
      path: "/",
      domain: ".thingmaker.repl.co"
    });
    await db.delete("session:"+sid).then(() => {
      resolve()
    }).catch(console.log)
  })
}
const validate = async(request, response, next) => {
  var sid = request.cookies ? request.cookies.sid : null
  if(sid) {
    await db.get("session:"+sid)
      .then(async(result) => {
        request.username = result.username
        next()
      }).catch((e) => response.status(401).send(/*"Invalid session id"*/""))
  } else {
    /*response.status(401).send*/console.log("An authorization header is required")
    next()
  }
}
async function isAdmin(username){
  var admin
  await db.get("user:"+username).then(r => {
    admin = r.admin
  }).catch(console.log)
  return admin
}
async function notif(data, username){
  await db.get("user:"+username).then(async u => {
    u.notifs = u.notifs || (u.notifs = [])
    u.notifs.push({
      notif:data,
      id: generateId(),
      read: false
    })
    await db.set("user:"+username, u).then(() => {})
  }).catch(console.log)
}
/*router.get('/setuser', (req, res)=>{
  setUser("user", res)
  res.send('user data added to cookie');
});
app.use('/setuser', router);*/
router.get('/getuser', validate, (req, res)=>{
  res.header("Content-Type", "text/plain")
  if(req.username){
    res.send(req.username)
    return
  }
  res.send("")
});

router.post("/register", async (request, response) => {
  await getPostData(request)

  if (!request.body.password) {
    return response.status(401).json({
      success: false,
      "message": "A `password` is required"
    })
  }else if (!request.body.username) {
    return response.status(401).json({
      success: false,
      "message": "A `username` is required"
    })
  }

  var exsists = false
  await db.list("user:"+request.body.username).then(matches => {
    if(matches.length){
      exsists = true
      response.status(401).json({
        success: false,
        message: "Account already exsists"
      })
    }
  }).catch(() => exsists = false)
  if(exsists){return}

  const id = generateId()
  const account = {
    "type": "account",
    "pid": id,
    "username": request.body.username,
    "password": bcrypt.hashSync(request.body.password, 10),
    pfp: "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mOU2jOnHgAEXQHz8u9NVQAAAABJRU5ErkJggg==",
    timestamp:(new Date()).getTime(),
  }
  
  db.set("user:"+account.username, account).then(() => {
    var session = {
        "type": "session",
        "id": generateId(),
        "pid": account.pid,
        "username": account.username
    }
    db.set("session:"+session.id, session)
        .then(() => {
          setUser(session.id, response)
          response.json({
            success:true,
            redirect:"/website/website.html"
          })
          console.log("New user", account.username)
        })
        .catch(e => response.status(500).send({success:false, message:e}))
  }).catch(e => response.status(500).send({success:false, message:e}));
})

router.post('/login', async (request, response) => {
  await getPostData(request)
  if (!request.body.username) {
    return response.status(401).send({success:false, "message": "An `username` is required" })
  } else if (!request.body.password) {
    return response.status(401).send({success:false, "message": "A `password` is required" })
  }
  
  await db.get("user:"+request.body.username)
    .then(async (result) => {
      if (!bcrypt.compareSync(request.body.password, result.password)) {
        return response.status(500).send({success:false, "message": "Password invalid" })
      }
      var session = {
        "type": "session",
        "id": generateId(),
        "pid": result.pid,
        "username": result.username
      }
      await db.set("session:"+session.id, session)
        .then(() => {
          setUser(session.id, response)
          response.json({
            success:true,
            redirect:"/website/website.html"
          })
        }).catch(e => response.status(500).send({success:false, message:e}))
    }).catch(e => response.status(500).send(e))
});
router.get("/account", validate, async (request, response) => {
  if(!request.username) return response.status(401).send('"Unauthorized"')
  try {
    await db.get("user:"+request.username)
      .then((result) => response.json(result))
      .catch((e) => response.status(500).send('"'+e+'"'))
  } catch (e) {
    console.error(e.message)
    response.status(500).send('"'+e+'"')
  }
})
//delete account
router.delete("/deleteAccount", validate, async (request, response) => {
  try {
    await logout(request, response)
    await db.delete("user:"+request.username)
      .then(() => {
        response.send("deleted")
        console.log("Deleted user", request.username)
      })
      .catch((e) => response.status(500).send(e))
  } catch (e) {
    console.error(e.message)
  }
})
router.get("/logout", async (request, response) => {
  await logout(request, response)
  response.send("Your'e logged out")
})
router.get("/account/*", async (request, response) => {
  let username = request.url.split("/").pop()
  try {
    await db.get("user:"+username)
      .then((result) => response.json(result))
      .catch((e) => response.status(500).send(e))
  } catch (e) {
    console.error(e.message)
  }
})
router.post("/changePfp", validate, async(req, res) => {
  if(!req.username) return res.json({message:"Unauthorized"})
  await getPostData(req)
  await db.get("user:"+req.username).then(r => {
    if(req.body.pfp) r.pfp = req.body.pfp
    if(req.body.bg) r.bg = req.body.bg
    db.set("user:"+req.username, r).then(() => {
      res.json({success:true, pfp:req.body.pfp, bg:req.body.bg})
    }).catch(e => res.json({message:e}))
  }).catch(e => res.json({message: e}))
})
router.post("/changePwd", validate, async(req, res) => {
  if(!req.username) return res.json({message:"Unauthorized"})
  await getPostData(req)
  db.get("user:"+req.username).then(r => {
    r.password = bcrypt.hashSync(req.body.pwd, 10)
    db.set("user:"+req.username, r).then(() => {
      res.json({success:true})
    }).catch(e => res.json({message:e}))
  }).catch(e => res.json({message: e}))
})
router.post("/changeBio", validate, async(req, res) => {
  if(!req.username) return res.status(401).json({message:"Unauthorized"})
  await getPostData(req)
  db.get("user:"+req.username).then(r => {
    r.bio = req.body.bio
    db.set("user:"+req.username, r).then(() => {
      res.json({success:true})
    }).catch(e => res.json({message:e}))
  }).catch(e => res.json({message: e}))
})
router.get("/users", (req, res) => {
  db.list("user:").then((users) => {res.json(users) })
})

var currentMedia = {
  type: "",
  data: ""
}
router.get("/currentMedia", async(req,res) => {
  if(currentMedia.data){
    res.header("Content-Type", currentMedia.type)
    res.end(currentMedia.data)
  }else res.send("")
})
router.post("/newMedia", async(req,res) => {
  await getPostText(req)
  var id = generateId()
  /*var buffer = Buffer.from(req.body)
  var prefix = "data:"+req.headers['content-type']+";base64,"
  var url = prefix + buffer.toString("base64").replace(/(\r\n|\n|\r)/gm,"")
  console.log(prefix)*/
  currentMedia.type = req.headers['content-type']
  currentMedia.data = Buffer.from(req.body, "base64")

  cloudinary.uploader.upload("https://server.thingmaker.repl.co/currentMedia", {
    public_id: id,
    resource_type: currentMedia.type.split("/")[0]
  }, function(error, result){
    if(error){
      console.log(error)
      return res.json({message: error})
    }
    res.json({success:true, url: result.secure_url})
    console.log("Media id:",id)
    console.log(result)
  })
})
// user makes a post/blog
router.post("/post", validate, async(request, response) => {
  await getPostData(request)
  if(!request.body.title) {
    return response.status(401).json({ "message": "A `title` is required" })
  } else if(!request.body.content) {
    return response.status(401).json({ "message": "A `content` is required" })
  }
  const uniqueId = generateId()
  var blog = {
    "type": "blog",
    "username": request.username,
    id:uniqueId,
    "title": request.body.title,
    "content": request.body.content,
    "followers":[request.username],
    "timestamp": (new Date()).getTime()
  }
  db.set("post:"+uniqueId, blog)
    .then(() => {
      response.json({
        success:true,
        data:blog,
        redirect: "/website/post.html?id="+uniqueId
      })
      console.log("New post", blog.title)
    })
    .catch((e) => response.status(500).json({message:e}))
})
router.delete("/deletePost/*", validate, async(req, res) => {
  let id = req.url.split("/").pop()
  var canDelete = false
  var title
  await db.get("post:"+id).then(async r => {
    title = r.title
    if(req.username === r.username){
      canDelete = true
    }else{
      await db.get("user:"+req.username).then(u => {
        if(u.admin) canDelete = true
      }).catch(() => res.send("error"))
    }
  }).catch(() => res.send("error"))

  if(!canDelete) return res.status(401).send("Your'e not authorized")
  db.delete("post:"+id).then(() => {
    res.send("ok")
    console.log("Deleted post", title)
  }).catch(() => res.send("error"))
})
//get a post by its id
router.get("/post/*", (request, res) => {
  let id = request.url.split("/").pop()
  db.get("post:"+id).then(data => {
    res.json(data)
  }).catch(() => res.send(null))
})
//get posts from a user
router.get("/posts/*", (req, res) => {
  let username = req.url.split("/").pop()
  db.list("post:").then(async matches => {
    var posts = []
    for(var i=0; i<matches.length; i++){
      await db.get(matches[i]).then(r => {
        if(r.username === username){
          posts.push(r)
        }
      })
    }
    res.json(posts)
  }).catch(() => res.send(null))
})
router.get("/posts", (req, res) => {
  db.list("post:").then(async matches => {
    var posts = []
    for(var i=0; i<matches.length; i++){
      await db.get(matches[i]).then(r => {
        posts.push(r)
      })
    }
    res.json(posts)
  }).catch(() => res.send(null))
})
router.post("/commentPost/*", validate, async(req, res) => {
  if(!req.username) return res.json({message:"Sign in to comment"})
  let id = req.url.split("/").pop()
  await getPostData(req)
  if(!req.body.comment){
    return res.json({message:"Comment cannot be blank."})
  }

  //get post and add comment and replace post
  //first comment on top
  var pfp
  await db.get("user:"+req.username).then(r => {
    pfp = r.pfp
  }).catch(e => res.json({message:e}))
  await db.get("post:"+id).then(async r => {
    var cid = generateId()
    r.comments = r.comments || []
    var commentData = {
      username:req.username,
      pfp:pfp,
      comment:req.body.comment,
      id: cid
    }
    r.comments.push(commentData)
    if(r.followers){
      for(var i=0; i<r.followers.length; i++){
        if(r.followers[i] !== req.username){
          await db.get("user:"+r.followers[i]).then(async u => {
            u.notifs = u.notifs || []
            u.notifs.push({
              notif:"New comment at <a href='/website/post.html?id="+id+"#comment"+cid+"'>"+r.title+"</a>",
              id: generateId(),
              read: false
            })
            await db.set("user:"+r.followers[i], u).then(() => {})
          }).catch(console.log)
        }
      }
    }
    db.set("post:"+id, r).then(() => {
      res.json({success:true, id:cid})
      sendPostWs({
        type:"comment",
        data:commentData
      }, id, req.body.userId)
      console.log("New comment at", r.title)
    })
  }).catch(() => {
    res.json({message:"Post doesn't exsist"})
  })
})
router.post("/followPost/*", validate, async(req, res) => {
  if(!req.username) return res.status(401).send("error")
  let id = req.url.split("/").pop()
  await getPostData(req)
  db.get("post:"+id).then(r => {
    var f = r.followers || (r.followers = [])
    if(req.body.follow){
      if(!f.includes(req.username)){
        f.push(req.username)
      }
    }else{
      var i = f.indexOf(req.username)
      if(i > -1){
        f.splice(i, 1)
      }
    }
    db.set("post:"+id, r).then(() => res.send("ok"))
  }).catch(() => {res.send("error")})
})
router.get("/comments/*", (req, res) => {
  let id = req.url.split("/").pop()
  db.get("post:"+id).then(r => {
    res.json(r.comments || [])
  }).catch(() => {res.send(null)})
})
router.get("/clearNotifs", validate, (req, res) => {
  if(!req.username) return res.status(401).send("Unauthorized")
  db.get("user:"+req.username).then(r => {
    for(var i=0; i<r.notifs.length; i++){
      var n = r.notifs[i]
      n.read = true
    }
    db.set("user:"+req.username, r).then(() => res.send("cleared")).catch(console.log)
  }).catch(console.log)
})
router.get("/sessions", (req, res) => {
  db.list("session:").then((d) => {res.json(d) })
})

//for minekhan
router.get("/worlds", (req, res) => {
  var data = []
  for(var i=0; i<worlds.length; i++){
    var w = worlds[i]
    data.push({
      name: w.name,
      players: (() => {
        var ps = []
        w.players.forEach(r => ps.push(r.username))
        return ps
      })(),
      id: w.id,
      host: w.host.username
    })
  }
  res.json(data)
})
router.post("/admin/messageUser/*", validate, async(req,res) => {
  if(!await isAdmin(req.username)) return res.json({message:"Unauthorized"})
  await getPostData(req)
  let to = req.url.split("/").pop()
  await notif(req.body.message, to)
  res.json({success:true})
})
app.use(router)

//404
app.use(function(req, res, next) {
  res.status(404);
  res.sendFile(__dirname + '/404.html');
});

let serverPort = app.listen(3000, function(){
  console.log("App server is running on port 3000");
});

//WebSocket
class WebSocketRoom{
  constructor(path){
    this.path = path
    this.onrequest = null
    this.connections = []

    WebSocketRoom.rooms.push(this)
  }
  static getRoom(path){
    for(var i=0; i<this.rooms.length; i++){
      if(this.rooms[i].path === path){
        return this.rooms[i]
      }
    }
  }
  static connection(request){
    let urlData = url.parse(request.httpRequest.url,true)
    let path = urlData.pathname
    var room = this.getRoom(path)
    if(room){
      const connection = request.accept(null, request.origin);
      room.connections.push(connection)
      room.onrequest(request, connection, urlData)
      connection.on("close", function(){
        var idx = room.connections.indexOf(connection)
        room.connections.splice(idx,1)
      })
    }
  }
}
WebSocketRoom.rooms = []
const wsServer = new WebSocketServer({
  httpServer: serverPort
})
wsServer.on("request", function(req){
  WebSocketRoom.connection(req)
})

//client side: var ws = new WebSocket("wss://server.thingmaker.repl.co/ws")
const minekhanWs = new WebSocketRoom("/ws");
var worlds = []
worlds.find = (id) => {
  for(var i=0; i<worlds.length; i++){
    if(worlds[i].id === id){
      return worlds[i]
    }
  }
}
minekhanWs.onrequest = function(request, connection, urlData) {
  const queryObject = urlData.query
  var target = queryObject.target || 0
  console.log("Client connected: ", queryObject)
  //add user to a world
  var world = worlds.find(target)
  if(world){
    world.players.push(connection)
  }else{
    world = {
      id: target,
      players: [connection],
      host: connection,
      name: target
    }
    worlds.push(world)
  }
  console.log(worlds.length+" worlds")
  function sendPlayers(msg){
    for(var i=0; i<world.players.length; i++){
      var p = world.players[i]
      if(p !== connection){
        p.sendUTF(msg)
      }
    }
  }
  function sendPlayer(msg, to){
    for(var i=0; i<world.players.length; i++){
      var p = world.players[i]
      if(p.id === to){
        p.sendUTF(msg)
      }
    }
  }
  function sendPlayerName(msg, to){
    for(var i=0; i<world.players.length; i++){
      var p = world.players[i]
      if(p.username === to){
        p.sendUTF(msg)
      }
    }
  }
  function closePlayers(){
    for(var i=0; i<world.players.length; i++){
      var p = world.players[i]
      if(p !== connection){
        p.close()
      }
    }
  }
  function closePlayer(id){
    for(var i=0; i<world.players.length; i++){
      var p = world.players[i]
      if(p.username === id){
        p.close()
      }
    }
  }
  connection.on('message', function(message) {
    var data = JSON.parse(message.utf8Data)
    if(data.type === "connect"){
      connection.id = data.id
      connection.username = data.username
      sendPlayers(JSON.stringify({
        type:"message",
        data: data.username+" joined. "+world.players.length+" players now.",
        username: "Server"
      }))
    }else if(data.type === "init"){
      world.name = data.name
    }else if(data.type === "pos" || data.type === "setBlock" || data.type === "getSave" || data.type === "message"){
      sendPlayers(message.utf8Data)
    }else if(data.type === "loadSave"){
      sendPlayer(message.utf8Data, data.TO)
    }else if(data.type === "kill"){
      if(data.data === "@a"){
        sendPlayers(JSON.stringify({type:"kill"}))
      }else{
        sendPlayerName('{"type":"kill"}', data.data)
      }
    }else if(data.type === "ban"){
      sendPlayerName(JSON.stringify({
        type:"error",
        data: "You've been banned from this world."
      }), data.data)
      closePlayer(data.data)
    }
  });
  connection.on('close', function(reasonCode, description) {
    console.log('Client has disconnected.');
    
    var idx = world.players.indexOf(connection)
    if(connection === world.host){
      closePlayers()
      worlds.splice(worlds.indexOf(world), 1)
      world = {}
    }else{
      sendPlayers(JSON.stringify({
        type:"dc",
        data: world.players[idx].id
      }))
      sendPlayers(JSON.stringify({
        type:"message",
        data: world.players[idx].username+" left. "+(world.players.length-1)+" players now.",
        username: "Server"
      }))
      world.players.splice(idx, 1)
    }
  });
};

var postWs = new WebSocketRoom("/postWs")
postWs.onrequest = function(req, connection, urlData){
  connection.postId = urlData.query.id
  connection.on("message", function(message){
    var packet = JSON.parse(message.utf8Data)
    if(packet.type === "connect"){
      connection.userId = packet.userId
    }
  })
}
function sendPostWs(obj, id, fromUserId){
  var str = JSON.stringify(obj)
  for(var i=0; i<postWs.connections.length; i++){
    var con = postWs.connections[i]
    if(con.postId === id && fromUserId !== con.userId) con.sendUTF(str)
  }
}

//console.clear()