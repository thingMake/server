/*
Useful functions:
LogAllOut()
promoteToAdmin(username)
deleteAccount(username)
banFromMineKhan(username,don't ban ip)
unbanFromMineKhan(username)
unpromoteFromAdmin(username)
giveCape(username,cape name)
*/

//Variables
var multiplayerOn = true
var multiplayerMsg = "testing & stuff" //message when multiplayer is off

process.on('unhandledRejection', (reason, p) => {
  console.error('Unhandled Rejection at: Promise', p, 'reason:', reason);
});

var d = ["2-people","2-people2"]

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
//const Database = require("@replit/database");
//const db = new Database()
const db = require("./db.js")
const bcrypt = require('bcrypt')
const WebSocketServer = require('websocket').server;
const url = require('url');
const cloudinary = require('cloudinary').v2
cloudinary.config({ 
  cloud_name: 'doooij2qr', 
  api_key: '525257699528752', 
  api_secret: process.env['cloudinary_api_secret']
});
const nodemailer = require('nodemailer');
const requestIp = require('request-ip');
app.use(requestIp.mw())
const Transform = require('stream').Transform;
const newLineStream = require('new-line');
const fs = require("fs")

var keysThisHour = 0
function updateKeysThisHour(){
  db.list().then(m => keysThisHour = m.length)
}
updateKeysThisHour()
setInterval(updateKeysThisHour, 1000*60*60)

let log = []
async function Log(){
  var data = []
  for(var i=0; i<arguments.length; i++){
    data.push(arguments[i])
  }
  console.log(...data)
  //var log = await db.get("log")
  //log = log || []
  log.push(data)
  await db.set("log", log)
}

function clearLog(){
  db.set("log",[]).then(() => {
    console.clear()
    log = []
  })
}
console.clear()
db.get("log").then(r => {
  r.forEach(v => {
    console.log(...v)
  })
  log = r
}).catch(() => {})

var bannedFromMineKhan
db.get("bannedFromMineKhan").then(r => {
  if(r){
    bannedFromMineKhan = r
    console.log("People banned from MineKhan: "+r.join(", "))
  }else{
    bannedFromMineKhan = []
  }
})
function banFromMineKhan(who, noIp){
  if(bannedFromMineKhan.includes("who")) return console.log(who+" is already banned.")
  db.get("user:"+who).then(r => {
    if(!r) return console.log(who+" doesn't exsist")
    bannedFromMineKhan.push(who)
    if(!noIp && r.ip) {
      for(var ip of r.ip){
        if(!bannedFromMineKhan.includes(ip)) bannedFromMineKhan.push(ip)
      }
    }
    db.set("bannedFromMineKhan", bannedFromMineKhan).then(() => console.log("done"))
  })
}
function unbanFromMineKhan(who){
  var i = bannedFromMineKhan.indexOf(who)
  if(i === -1) return console.log(who+" is not on the banned list")
  bannedFromMineKhan.splice(i,1)
  db.get("user:"+who).then(r => {
    if(r.ip){
      for(var j=0; j<r.ip.length; j++){
        var i = bannedFromMineKhan.indexOf(r.ip[j])
        if(i === -1) console.log(who+" is not on the banned list")
        else bannedFromMineKhan.splice(i,1)
      }
    }
    db.set("bannedFromMineKhan", bannedFromMineKhan).then(() => console.log("done"))
  })
}

var capes = {}
db.get("capes").then(r => {
  if(r) capes = r
})
function saveCapes(){
  return db.set("capes",capes) //return promise
}
async function giveCape(username, name){
  await db.get("user:"+username).then(async u => {
    u.ownedCapes = u.ownedCapes || []
    u.ownedCapes.push(name)
    await db.set("user:"+username, u)
    console.log("done")
  }).catch(e => Log(e))
}

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

function valueToString(v, nf){ //for log
  var str = ""
  if(typeof v === "function"){
    str = "<span style='color:purple;'>"+v.toString()+"</span>"
  }else if(Array.isArray(v)){
    str = "<span style='color:red;'>["
    for(var i=0; i<v.length; i++){
      str += valueToString(v[i], true)+", "
    }
    if(v.length)str = str.substring(0, str.length-2) //remove trailing ", "
    str += "]</span>"
  }else if(typeof v === "object"){
    str = "<span style='color:red;'>{"
    var hasTrailing
    for(var i in v){
      str += "<span style='color:blue;'>"+i+"</span>: "+valueToString(v[i], true)+", "
      hasTrailing = true
    }
    if(hasTrailing)str = str.substring(0, str.length-2) //remove trailing ", "
    str += "}</span>"
  }else if(typeof v === "number"){
    str = "<span style='color:orange;'>"+v.toString()+"</span>"
  }else if(typeof v === "string"){
    if(v.startsWith("MineKhan")){
      v = v.replace(/&/g,"&amp;")
      v = v.replace(/</g,"&lt;")
      v = v.replace(/>/g,"&gt;")
      v = v.replace("MineKhan","<span style='background:yellow;'>MineKhan</span>")
    }
    if(v.startsWith("New comment")){
      v = v.replace("comment","<span style='background:orange;'>comment</span>")
    }
    if(v.startsWith("New post") || v.startsWith("Edited post")){
      v = v.replace("post","<span style='background:orange;'>post</span>")
    }
    v = v.replace(/(added cape|removed cape)/, "<span style='background:#88f;'>$1</span>")
    v = v.replace(/(changed their bio|changed their skin|changed their cape)/, "<span style='background:lightgreen;'>$1</span>")

    v = v.replace(/%>/g, "<b style='color:orange; margin-right:15px;'>&gt;</b>")
    v = v.replace(/%</g, "<b style='color:orange; margin-right:15px;'>&nbsp;</b>")//⋖
    if(nf)str = "<span style='color:green;'>'"+v+"'</span>" 
    else str = v
  }else str = v
  return str
}

router.get('/', function(req, res){
  res.sendFile(path.join(__dirname, "/info.html"));
});

router.get('/test', function(req, res){
  res.send("test")
});
router.get('/log', async(req,res) => {
  var options = url.parse(req.url,true).query
  var log = await db.get("log")
  if(!log || !log.length) return res.send("Empty")
  var str = "<style>#logContent>span{max-width:100%;text-overflow:ellipsis;white-space:nowrap;display:inline-block;overflow:hidden;}</style><div id='logContent' style='font-family:monospace;'>"
  log.forEach(v => {
    if(options.nominekhan && typeof v[0] === "string" && v[0].startsWith("MineKhan: ")) return
    str += "<span>"
    v.forEach(r => {
      str += valueToString(r)+" "
    })
    str += "</span><br>"
  })
  str += "</div>"
  str += "<br><br>"
  str += "People banned from MineKhan: "+bannedFromMineKhan.join(", ")
  res.send(str)
})
/*router.get("/pfp.png", (req,res) => {
  res.sendFile(__dirname+"/pfp.png")
})*/
router.get("/panorama", (req,res) => {
  res.redirect("https://data.thingmaker.repl.co/images/panorama/summer.png")
})

router.get("/common.js", (req,res) => {
  var str = ""
  if(keysThisHour > Infinity){
    str += "addBanner('Server low on or out of space. Please delete unused accounts and posts to allow other users to create accounts and login.');"
  }
  res.header("Content-Type", "application/javascript")
  res.send(str)
})

app.use(express.static('public'))

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
    }).catch(e => {Log(e)})
  })
}

const validate = async(request, response, next) => {
  var sid = request.cookies ? request.cookies.sid : null
  if(sid) {
    await db.get("session:"+sid)
      .then(async(result) => {
        if(!result) return next()
        request.username = result.username
        db.get("user:"+request.username).then(u => {
          if(u){
            u.ip = u.ip || []
            if(request.clientIp && !u.ip.includes(request.clientIp)) {
              u.ip.push(request.clientIp)
            }
            u.lastActive = Date.now()
            db.set("user:"+request.username, u).then(() => {
              next()
            })
          }else{
            request.username = null
            next()
          }
        })
      }).catch((e) => response.status(401).send(/*"Invalid session id"*/""))
  } else {
    /*response.status(401).send*///console.log("Not logged in")
    next()
  }
}

async function isAdmin(username){
  var admin
  await db.get("user:"+username).then(r => {
    admin = r.admin
  }).catch(e => Log(e))
  return admin
}
async function notif(data, username){
  await db.get("user:"+username).then(async u => {
    u.notifs = u.notifs || []
    u.notifs.push({
      notif:data,
      id: generateId(),
      read: false
    })
    await db.set("user:"+username, u).then(() => {})
  }).catch(e => Log(e))
}
function addNotif(data, u){
  u.notifs = u.notifs || []
  u.notifs.push({
    notif:data,
    id: generateId(),
    read: false
  })
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
  }else if (request.body.username.length > 15){
    return response.json({
      success:false,
      message: "Username can only have less than 15 characters."
    })
  }

  if(request.body.username.match(/[^a-zA-Z0-9\-_]/)){
    return response.json({message:"Username can only contain characters: A-Z, a-z, 0-9, - and _"})
  }

  var exsists = false
  await db.get("user:"+request.body.username).then(u => {
    if(u){
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
    email:request.body.email,
    pfp: "https://server.thingmaker.repl.co/pfp.png",
    timestamp:Date.now(),
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
          Log("New user", account.username)
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
        Log("Deleted user", request.username)
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
router.get("/getSession", async (req,res) => {
  var sid = req.cookies ? req.cookies.sid : null
  var s
  if(sid){
    s = await db.get("session:"+sid)
  }
  if(s){
    s = s.id
  }else{
    s = null
  }
  
  var parser = new Transform({
    transform(data, encoding, done) {
      const str = data.toString().replace('SESSION', s);
      this.push(str);
      done();
    }
  })

  res.header("Content-Type","text/html")
  
  fs.createReadStream(__dirname+'/getSession.html')
    .pipe(newLineStream())
    .pipe(parser)
    .on("error",e => {
      console.error(e)
    })
    .pipe(res);
})
router.get("/account/*", async (request, response, next) => {
  let username = request.params[0]
  if(username.includes("/")) return next()
  try {
    await db.get("user:"+username)
      .then(result => {
        delete result.ip
        delete result.notifs
        delete result.password
        response.json(result)
      })
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
  Log(req.username+" changed their password")
})
router.post("/changeEmail", validate, async(req, res) => {
  if(!req.username) return res.json({message:"Unauthorized"})
  await getPostData(req)
  db.get("user:"+req.username).then(r => {
    r.email = req.body.email
    db.set("user:"+req.username, r).then(() => {
      res.json({success:true})
    }).catch(e => res.json({message:e}))
  }).catch(e => res.json({message: e}))
  Log(req.username+" changed their email")
})
router.post("/changeBio", validate, async(req, res) => {
  if(!req.username) return res.status(401).json({message:"Unauthorized"})
  await getPostData(req)
  db.get("user:"+req.username).then(r => {
    r.bio = req.body.bio
    db.set("user:"+req.username, r).then(() => {
      res.json({success:true})
      Log(req.username+" changed their bio.")
    }).catch(e => res.json({message:e}))
  }).catch(e => res.json({message: e}))
})
router.post("/changeSkin", validate, async(req, res) => {
  if(!req.username) return res.status(401).json({message:"Unauthorized"})
  await getPostData(req)
  if(!req.body.skin) return res.json({message:"Please set a skin"})
  db.get("user:"+req.username).then(r => {
    r.skin = req.body.skin
    db.set("user:"+req.username, r).then(() => {
      res.json({success:true})
      Log(req.username+" changed their skin.")
    }).catch(e => res.json({message:e}))
  }).catch(e => res.json({message: e}))
})

router.get("/capes", (req,res) => {
  res.json(capes)
})
router.get("/cape/*", (req,res) => {
  let name = unescape(req.params[0])
  res.send(capes[name] || "null")
})
router.post("/equipCape", validate, async(req,res) => {
  if(!req.username) return res.status(401).json({message:"Unauthorized"})
  await getPostData(req)
  var user = await db.get("user:"+req.username)
  if(user.admin && req.body.cape && !user.ownedCapes.includes(req.body.cape)) user.ownedCapes.push(req.body.cape)
  if(!req.body.cape){
    delete user.cape
    await db.set("user:"+req.username,user)
    res.json({success:true})
    Log(req.username+ " changed their cape.")
  }else if(user.ownedCapes.includes(req.body.cape)){
    user.cape = capes[req.body.cape]
    await db.set("user:"+req.username,user)
    res.json({success:true})
    Log(req.username+ " changed their cape.")
  }else{
    res.json({message:"you don't own it"})
  }
})
router.post("/addCape", validate, async(req,res) => {
  if(!req.username) return res.status(401).json({message:"Unauthorized"})
  var user = await db.get("user:"+req.username)
  if(!user.admin) return res.json({message:"no permission"})
  await getPostData(req)
  if(!req.body.name) return res.json({message:"It needs a name."})
  capes[req.body.name] = req.body.url
  await saveCapes()
  res.json({success:true})
  Log(req.username+" added cape "+req.body.name)
})
router.post("/removeCape", validate, async(req,res) => {
  if(!req.username) return res.status(401).json({message:"Unauthorized"})
  var user = await db.get("user:"+req.username)
  if(!user.admin) return res.json({message:"no permission"})
  await getPostData(req)
  if(!capes[req.body.name]) return res.json({message:"invalid name"})
  delete capes[req.body.name]
  await saveCapes()
  res.json({success:true})
  Log(req.username+" removed cape "+req.body.name)
})

router.get("/deleteNotifs", validate, (req,res) => {
  if(!req.username) return res.status(401).json({message:"Unathorized"})
  db.get("user:"+req.username).then(r => {
    delete r.notifs
    db.set("user:"+req.username, r).then(() => {
      res.json({success:true})
      Log(req.username+" deleted their notifications.")
    }).catch(e => res.json({message:e}))
  }).catch(e => res.json({message: e}))
})
router.get("/pfp/*", async(req,res) => {
  let username = req.url.split("/").pop()
  db.get("user:"+username).then(d => {
    /*fetch(d.pfp, (err,meta,body) => {
      if(err){
        console.log(err)
        return res.send("error")
      }
      res.send(body)
    })*/
    res.redirect(d.pfp)
  }).catch(() => res.send("error"))
})
router.get("/skin/*", async(req,res) => {
  let username = req.url.split("/").pop()
  db.get("user:"+username).then(d => {
    var data = d.skin.replace(/^data:image\/png;base64,/, '');
    var img = Buffer.from(data, 'base64');
    res.writeHead(200, {
      'Content-Type': 'image/png',
      'Content-Length': img.length
    });
    res.end(img);
  }).catch(() => res.send("error"))
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
      Log(error)
      return res.json({message: error})
    }
    res.json({success:true, url: result.secure_url})
    Log("Media id:",id)
  })
})
// user makes a post/blog
router.post("/post", validate, async(request, response) => {
  if(!request.username){
    return response.status(401).json({message:"You need to login to create posts. Login is at the top right."})
  }
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
    "timestamp": Date.now()
  }
  db.set("post:"+uniqueId, blog)
    .then(() => {
      response.json({
        success:true,
        data:blog,
        redirect: "/website/post.html?id="+uniqueId
      })
      Log("New post", "<a href='/website/post.html?id="+blog.id+"' target='_blank'>"+blog.title+"</a>")
    })
    .catch((e) => response.status(500).json({message:e}))
})
router.delete("/deletePost/*", validate, async(req, res) => {
  let id = req.url.split("/").pop()
  var canDelete = false
  var adminDelete = false
  var title
  var author
  await db.get("post:"+id).then(async r => {
    title = r.title
    author = r.username
    if(req.username === r.username){
      canDelete = true
    }else{
      await db.get("user:"+req.username).then(u => {
        if(u.admin){
          canDelete = true
          adminDelete = true
        }
      }).catch(() => res.send("error"))
    }
  }).catch(() => res.send("error"))

  if(!canDelete) return res.status(401).send("Your'e not authorized")
  db.delete("post:"+id).then(async() => {
    if(adminDelete) await notif(req.username+" deleted your post: "+title, author)
    res.send("ok")
    Log("Deleted post", title)
  }).catch(e => {res.send("error"); console.log(e)})
})
router.post("/editPost/*", validate, async(req, res) => {
  let id = req.url.split("/").pop()
  if(!req.username){
    return response.status(401).json({message:"You need to login to edit your posts. Login is at the top right."})
  }
  await getPostData(req)
  var post = await db.get("post:"+id)
  if(!post) return res.json({message:"post does not exist"})

  var user = await db.get("user:"+req.username)
  var canEdit = false
  if(post.username === req.username) canEdit = true
  if(user.admin) canEdit = true
  if(!canEdit) return res.json({message:"You do not have permission to edit this post."})
  
  if(!req.body.content) return res.json({message:"You need content for the post."})
  if(req.body.content === post.content) return res.json({message:"You did not change the content."})

  post.content = req.body.content
  await db.set("post:"+id, post)
  res.json({success:true})
  Log("Edited post <a href='/website/post.html?id="+id+"' target='_blank'>"+post.title+"</a>")
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
          posts.push({
            username:r.username,
            id:r.id,
            title:r.title,
            timestamp:r.timestamp
          })
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
        posts.push({
          username:r.username,
          id:r.id,
          title:r.title,
          timestamp:r.timestamp
        })
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
      //pfp:pfp,
      comment:req.body.comment,
      id: cid,
      timestamp:Date.now()
    }
    r.comments.push(commentData)
    if(r.followers){
      for(var i=0; i<r.followers.length; i++){
        if(r.followers[i] !== req.username){
          await db.get("user:"+r.followers[i]).then(async u => {
            if(!u){
              var who = r.followers[i]
              Log(who+" doesn't exsist but is following "+r.title)
              r.followers.splice(i, 1)
              i --
              Log("Removed "+who+" from following "+r.title)
              return
            }
            u.notifs = u.notifs || []
            u.notifs.push({
              notif: req.username+" commented at <a href='/website/post.html?id="+id+"#comment"+cid+"'>"+r.title+"</a>",
              id: generateId(),
              read: false
            })
            await db.set("user:"+r.followers[i], u).then(() => {})
          }).catch(e => Log(e))
        }
      }
    }
    db.set("post:"+id, r).then(() => {
      res.json({success:true, id:cid})
      sendPostWs({
        type:"comment",
        data:commentData
      }, id, req.body.userId)
      Log("New comment at", "<a href='/website/post.html?id="+r.id+"#comment"+cid+"' target='_blank'>"+r.title+"</a>")
    })
  }).catch(() => {
    res.json({message:"Post doesn't exsist"})
  })
})
router.post("/deletePostComment/*", validate, async(req,res) => {
  if(!req.username) return res.status(401).send("error")
  let id = req.url.split("/").pop()
  await getPostData(req)
  db.get("post:"+id).then(async d => {
    var canDelete, sendNotif
    let cid = req.body.cid
    var c
    for(var i=0; i<d.comments.length; i++){
      if(d.comments[i].id == cid){
        c = d.comments[i]
        break
      }
    }
    if(c.username === req.username){//creator of comment delete the comment
      canDelete = true
    }else if(req.username === d.username){//creator of post delete the comment
      sendNotif = canDelete = true
    }else{//admin delete comment
      await db.get("user:"+req.username).then(r => {
        if(r.admin) sendNotif = canDelete = true
      })
    }
    if((!c) || (!canDelete)) return res.send("error")
    c.hide = true
    db.set("post:"+id, d).then(async() => {
      res.send("ok")
      if(sendNotif) await notif(req.username+" deleted your comment at: "+d.title, c.username)
      sendPostWs({
        type:"deleteComment",
        data: cid
      }, id, req.body.userId)
      Log("Deleted comment at", d.title)
    })
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
router.get("/getLocalTime/", (req,res) => {
  if(!req.query.time) return res.json({message:"need time parameter"})
  var diff = Date.now() - parseFloat(req.query.time)
  if(req.query.convert){
    res.json({success:true,time:parseFloat(req.query.convert)+diff})
  }else{
    res.json({success:true,diff})
  }
})
router.get("/clearNotifs", validate, (req, res) => {
  if(!req.username) return res.status(401).send("Unauthorized")
  db.get("user:"+req.username).then(r => {
    for(var i=0; i<r.notifs.length; i++){
      var n = r.notifs[i]
      n.read = true
    }
    db.set("user:"+req.username, r).then(() => res.send("cleared")).catch(e => Log(e))
  }).catch(e => Log(e))
})

router.post("/resetPwd", async (req,res) => {
  return res.json({message:"Functionality not available yet"})

  await getPostData(req)
  var username = req.body.username
  db.get("user:"+username).then(r => {
    if(!r) return res.json({message:"That account doesn't exsist."})
    var email = r.email || ""
    if(!email){
      return res.json({message:"Sorry, that account doesn't have an email."})
    }
    var transport = nodemailer.createTransport({
      /*host: "smtp.gmail.com",
      port: 2525,*/
      service:"gmail",
      auth: {
        user: "minekhanteam@gmail.com",
        pass: process.env['gmail_pass']
      }
    });
    var message = {
      from: "reset_password@thingmaker.repl.co",
      to: email,
      subject: "Reset Password",
      html: `
<h1>So, you decided to reset your password, huh?</h1>
<p>All you have to do is follow the instructions.</p>
<ol>
  <li>Click <a>here</a></li>
</ol>
`
    }
    transport.sendMail(message, function(err, info) {
      if (err) {
        res.json({message:JSON.stringify(err)})
      } else {
        Log("Reset password email sent to "+req.username,info);
        res.json({success:true})
      }
    })
  })
})

router.get("/sessions", (req, res) => {
  const pwd = process.env['pwd']
  var urlData = url.parse(req.url,true)
  var q = urlData.query.pwd
  if(q === pwd){
    db.list("session:").then((d) => {res.json(d) })
  }else{
    res.sendFile(__dirname+"/401.html")
  }
})
router.get("/findEmail/*", async(req,res) => {
  var search = req.params[0]
  if(!search) return res.end()
  var users = await db.list("user:",true)
  for(var i in users){
    var u = users[i]
    if(u.email && u.email.includes(search)) res.write(i+": "+u.email+"\n")
  }
  res.end()
})
router.get("/findSimilarUsers/*", async(req,res) => {
  var search = req.params[0]
  if(!search) return res.end()
  var user = await db.get("user:"+search)
  if(!user) return res.send("invalid username")
  var ip = user.ip
  if(!ip) return res.send("user has no ip")
  var users = await db.list("user:",true)
  userLoop:for(var i in users){
    var u = users[i]
    if(!u.ip) continue
    for(var i2 of u.ip) if(ip.includes(i2)){
      res.write(u.username+"\n")
      continue userLoop
    }
  }
  res.end()
})

//cloud saves
router.get("/saves", validate, async(req,res) => {
  if(!req.username) return res.status(401).json("Unauthorized")
  var saves = await db.get("saves:"+req.username)
  if(!saves) return res.json(null)
  for(var i=0; i<saves.length; i++){
    var s = saves[i]
    saves[i] = {
      edited:s.edited,
      id:s.id,
      name:s.name,
      thumbnail:s.thumbnail,
      version:s.version,
      size:s.code ? s.code.length : 0
    }
  }
  res.json(saves)
})
router.get("/saves/*", validate, async(req,res) => {
  if(!req.username) return res.status(401).json("Unauthorized")
  var saves = await db.get("saves:"+req.username)
  if(!saves) return res.json(null)
  let id = req.params[0]
  for(var i=0; i<saves.length; i++){
    var s = saves[i]
    if(s.id.toString() === id) return res.json(s)
  }
  res.json(null)
})
router.post("/saves", validate, async(req,res) => {
  if(!req.username) return res.status(401).json("Unauthorized")
  await getPostData(req)
  var save = req.body
  if(!save || !save.id) res.json({message:"invalid save"})
  var saves = await db.get("saves:"+req.username) || []
  var found = false
  for(var i=0; i<saves.length; i++){
    if(saves[i].id === save.id){
      saves[i] = save
      found = true
    }
  }
  if(!found) saves.push(save)
  await db.set("saves:"+req.username, saves)
  res.json({success:true})
})
router.delete("/saves/*", validate, async(req,res) => {
  if(!req.username) return res.status(401).json("Unauthorized")
  var saves = await db.get("saves:"+req.username)
  if(!saves) return res.json({message:"save doesn't exist"})
  let id = req.params[0]
  for(var i=0; i<saves.length; i++){
    var s = saves[i]
    if(s.id.toString() === id){
      saves.splice(i,1)
      await db.set("saves:"+req.username, saves)
      return res.json({success:true})
    }
  }
  res.json({message:"save doesn't exist"})
})
router.get("/account/*/saves", async(req,res) => {
  let username = req.params[0]
  var saves = await db.get("saves:"+username)
  res.json(saves)
})

//for minekhan
router.get("/worlds", (req, res) => {
  res.json(worlds.toRes())
})
router.get("/worldsPing", (req, res) => {
  var w = []
  for(var i=0; i<worlds.length; i++){
    var world = worlds[i]
    w.push(pingWorld(world.id))
  }
  Promise.all(w).then(w => {
    var data = {}
    for(var i=0; i<w.length; i++){
      data[worlds[i].id] = w[i]
    }
    res.json(data)
  })
})

router.post("/admin/messageUser/*", validate, async(req,res) => {
  if(!await isAdmin(req.username)) return res.json({message:"Unauthorized"})
  await getPostData(req)
  let to = req.url.split("/").pop()
  await notif(req.username+" sent message: "+req.body.message, to)
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

function LogAllOut(){
  db.list("session:").then(m => {
    var p = []
    for(var i=0; i<m.length; i++){
      p.push(db.delete(m[i]))
    }
    Promise.all(p).then(() => {
      console.log("Done")
    })
  })
}
function deleteAccount(username){
  db.delete("user:"+username).then(() => console.log("done"))
}
function promoteToAdmin(username){
  db.get("user:"+username).then(r =>{
    if(!r) return console.log("user doesn't exsist")
    r.admin = true
    addNotif("You have been promoted to admin",r)
    db.set("user:"+username, r).then(() => console.log("done"))
  })
}
function unpromoteFromAdmin(username){
  db.get("user:"+username).then(r =>{
    if(!r) return console.log("user doesn't exsist")
    r.admin = false
    addNotif("You have been unpromoted from admin",r)
    db.set("user:"+username, r).then(() => console.log("done"))
  })
}

//WebSocket
class WebSocketRoom{
  constructor(path){
    this.path = path
    this.onrequest = null
    this.connections = []
    this.validateFunc = null

    WebSocketRoom.rooms.push(this)
  }
  static getRoom(path){
    for(var i=0; i<this.rooms.length; i++){
      if(this.rooms[i].path === path){
        return this.rooms[i]
      }
    }
  }
  static async connection(request){
    let urlData = url.parse(request.httpRequest.url,true)
    let path = urlData.pathname
    var room = this.getRoom(path)
    if(room){
      var valid = true
      var options = {send:null}
      if(room.validateFunc){
        valid = await room.validateFunc(request, options)
      }
      const connection = request.accept(null, request.origin);
      if(options.send) connection.sendUTF(options.send)
      if(!valid){
        return connection.close()
      }
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
wsServer.on("request", req => WebSocketRoom.connection(req))

//client side: var ws = new WebSocket("wss://server.thingmaker.repl.co/ws")
const minekhanWs = new WebSocketRoom("/ws");

//Function to validate request
minekhanWs.validateFunc = async (request, options) => {
  if(request.origin !== "https://minekhan.thingmaker.repl.co"){
    return false
  }
  var ip = requestIp.getClientIp(request)
  if(bannedFromMineKhan.includes(ip)){
    return false
  }

  var sid
  for(var i=0; i<request.cookies.length; i++){
    var c = request.cookies[i]
    if(c.name === "sid"){
      sid = c.value
      break
    }
  }
  if(sid) {
    var l = await db.get("session:"+sid)
      .then(async result => {
        if(!result) return false
        if(await db.get("user:"+result.username).then(u => {
          if(u) request.isAdmin = u.admin || false, request.username = u.username
          else return true
        })){
          return false
        }
        return result.username
      })
    if(!l) return false
  }else return false
  
  if(!multiplayerOn && !d.includes(request.username)){
    options.send = JSON.stringify({
      type:"error",
      data:multiplayerMsg
    })
    return false
  }
  
  return true
}

var worlds = []
worlds.find = (id) => {
  for(var i=0; i<worlds.length; i++){
    if(worlds[i].id === id){
      return worlds[i]
    }
  }
}
worlds.toRes = function(){
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
      host: w.host.username,
      banned: w.banned,
      whitelist: w.whitelist
    })
  }
  return data
}
worlds.pings = {}
async function pingWorld(id){
  var w = worlds.find(id)
  if(!w) return "error"
  var start = Date.now()
  var ms = await new Promise((resolve,reject) => {
    var resolved = false
    worlds.pings[id] = {
      id: id,
      done: f => {
        var finish = Date.now()
        var ms = (finish - start)
        resolve(ms)
        resolved = true
      }
    }
    w.host.sendUTF(JSON.stringify({
      type:"ping"
    }))
    setTimeout(() => {
      if(!resolved){
        resolve("timeout")
      }
    }, 20000)
  })
  return ms
}

worlds.sendEval = function(index, player, data){
  Log("%>worlds["+index+"].players["+player+"].sendUTF('{\"type\":\"eval\",\"data\":\""+data+"\"}')")
  var world = worlds[index]
  if(!world) return Log("%<Error: worlds["+index+"] is not defined")
  if(player === "@a"){
    world.players.forEach(p => {
      p.sendUTF(JSON.stringify({type:"eval",data:data}))
    })
  }else{
    var p = world.players[player]
    if(!p) return Log("%<Error: worlds["+index+"].players["+player+"] is not defined")
    p.sendUTF(JSON.stringify({type:"eval",data:data}))
  }
  Log("%<Eval data sent.")
}

minekhanWs.onrequest = function(request, connection, urlData) {
  const queryObject = urlData.query
  var target = queryObject.target
  if(!(target||target===0)){
    connection.close()
    return
  }
  
  Log("MineKhan: Client connected: ", queryObject)
  connection.isAdmin = request.isAdmin
  var username = connection.username = request.username

  //add user to a world
  var world = worlds.find(target)
  if(world){
    world.players.push(connection)
  }else{
    if(worlds.length >= 5){
      connection.sendUTF(JSON.stringify({
        type:"error",
        data:"Only 5 servers at a time"
      }))
      connection.close()
      return
    }
    world = {
      id: target,
      players: [connection],
      banned: {},
      whitelist: null,
      host: connection,
      name: "Ghost server "+target
    }
    worlds.push(world)
  }
  connection.sendJSON = function(o){
    if(typeof o === "object") o = JSON.stringify(o)
    this.sendUTF(o)
  }
  function sendPlayers(msg){
    for(var i=0; i<world.players.length; i++){
      var p = world.players[i]
      if(p !== connection){
        p.sendJSON(msg)
      }
    }
  }
  function sendAllPlayers(msg){
    for(var i=0; i<world.players.length; i++){
      var p = world.players[i]
      p.sendJSON(msg)
    }
  }
  function sendPlayer(msg, to){
    for(var i=0; i<world.players.length; i++){
      var p = world.players[i]
      if(p.id === to){
        p.sendJSON(msg)
      }
    }
  }
  function sendThisPlayer(msg){
    connection.sendJSON(msg)
  }
  function sendPlayerName(msg, to){
    for(var i=0; i<world.players.length; i++){
      var p = world.players[i]
      if(p.username === to){
        p.sendJSON(msg)
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
  function closeThisPlayer(){
    connection.close()
  }
  function findPlayer(id){
    for(var i=0; i<world.players.length; i++){
      var p = world.players[i]
      if(p.username === id){
        return p
      }
    }
  }
  connection.on('message', function(message) {
    var data
    try{
      data = JSON.parse(message.utf8Data)
    }catch{
      return
    }
    if(data.type === "connect"){
      if(bannedFromMineKhan.includes(username)){
        sendThisPlayer(JSON.stringify({
          type:"error",
          data:"You are banned from MineKhan."
        }))
        connection.close()
        return
      }

      if(username in world.banned){
        if(connection.isAdmin){
          delete world.banned[username]
        }else{
          var b = world.banned[username]
          sendThisPlayer(JSON.stringify({
            type:"error",
            data: "You've been banned from this world." + (b ? "\n\n\n\n\nReason:\n"+b : "")
          }))
          sendAllPlayers(JSON.stringify({
            type:"message",
            username:"Server",
            data:username+" was banned and tried to join ",
            fromServer:true
          }))
          Log("MineKhan: "+username+" was banned but tried to join "+world.name)
          closeThisPlayer()
          return
        }
      }
      if(world.whitelist && !world.whitelist.includes(username) && !connection.isAdmin){
        sendThisPlayer(JSON.stringify({
          type:"error",
          data: "You have not been whitelisted on this server."
        }))
        closeThisPlayer()
        return
      }

      connection.id = data.id
      //connection.username = data.username
      sendPlayers(JSON.stringify({
        type:"message",
        data: username+" is connecting. "+world.players.length+" players now.",
        username: "Server",
        fromServer:true
      }))
      Log("MineKhan: "+username+" joined the server: "+world.name)
    }else if(data.type === "joined"){
      sendPlayers(JSON.stringify({
        type:"message",
        data: username+" joined. ",
        username: "Server",
        fromServer:true
      }))
    }else if(data.type === "init"){
      world.name = data.name
      Log("MineKhan: "+username+" opened server: "+world.name, worlds.length+" worlds")
      worldsChanged()
    }else if(data.type === "pong"){
      var p = worlds.pings[world.id]
      if(p){
        p.done(data.data)
      }
    }else if(data.type === "pos"){
      sendPlayers(message.utf8Data)
      sendThisPlayer(JSON.stringify({
        type:"canSendPos"
      }))
    }else if(data.type === "message" || data.type === "die"){
      data.username = username
      sendPlayers(JSON.stringify(data))
    }else if(data.type === "setBlock" || data.type === "getSave" || data.type === "entityPos" || data.type === "entityPosAll" || data.type === "entityDelete" || data.type === "harmEffect" || data.type === "achievment" ||  data.type === "playSound" || data.type === "mySkin" || data.type === "setTags"){
      sendPlayers(message.utf8Data)
    }else if(data.type === "hit"){
      data.username = username
      sendPlayer(JSON.stringify(data), data.TO)
    }else if(data.type === "loadSave" || data.type === "loadSaveChunk"){
      sendPlayer(message.utf8Data, data.TO)
    }else if(data.type === "kill"){
      if(data.data === "@a"){
        sendPlayers(JSON.stringify({type:"kill",data:data.message}))
      }else{
        sendPlayerName(JSON.stringify({
          type:"kill",
          data:data.message
        }), data.data)
      }
    }else if(data.type === "diamondsToYou"){
      sendPlayer(JSON.stringify({
        type:"diamondsToYou"
      }), data.TO)
    }else if(data.type === "ban"){
      if(!(connection === world.host || connection.isAdmin)) return sendThisPlayer(JSON.stringify({
          type:"message",
          username:"Server",
          data:"You dont have permission to ban.",
          fromServer:true
        }))
      
      var banWho = findPlayer(data.data)
      if(banWho && banWho.isAdmin){
        sendPlayer(JSON.stringify({
          type:"message",
          username:"Server",
          data:"You can't ban "+data.data,
          fromServer:true
        }), data.FROM)
        sendPlayers(JSON.stringify({
          type:"message",
          username:"Server",
          data: "The host tried to ban "+data.data+".",
          fromServer:true
        }))
        return
      }

      if(data.data in world.banned){
        return sendThisPlayer(JSON.stringify({
          type:"message",
          username:"Server",
          data:data.data+" is already banned.",
          isServer:true
        }))
      }else{
        world.banned[data.data] = data.reason || ""
      }
      
      sendPlayerName(JSON.stringify({
        type:"error",
        data: "You've been banned from this world." + (data.reason ? "\n\n\n\n\nReason:\n"+data.reason : "")
      }), data.data)
      sendAllPlayers(JSON.stringify({
        type:"message",
        username:"Server",
        data:data.data+" got banned.",
        fromServer:true
      }))
      Log("MineKhan: "+data.data+" got banned from the server: "+world.name)
      closePlayer(data.data)
    }else if(data.type === "unban"){
      if(!(connection === world.host || connection.isAdmin)) return sendThisPlayer(JSON.stringify({
          type:"message",
          username:"Server",
          data:"You dont have permission to unban.",
          fromServer:true
        }))
      
      if(!(data.data in world.banned)){
        return sendThisPlayer(JSON.stringify({
          type:"message",
          username:"Server",
          data:data.data+" is not banned.",
          fromServer:true
        }))
      }
      delete world.banned[data.data]
      sendAllPlayers(JSON.stringify({
        type:"message",
        username:"Server",
        data:data.data+" got unbanned.",
        fromServer:true
      }))
      Log("MineKhan: "+data.data+" got unbanned from the server: "+world.name)
    }else if(data.type === "whitelist"){
      if(!(connection === world.host || connection.isAdmin)) return sendThisPlayer(JSON.stringify({
          type:"message",
          username:"Server",
          data:"You dont have permission to edit whitelist.",
          fromServer:true
        }))

      if((data.data === "add" || data.data === "remove") && !world.whitelist) return sendThisPlayer(JSON.stringify({
          type:"message",
          data: "You need to enable whitelist to do that.",
          username: "Server",
          fromServer:true
        }))
      
      if(data.data === "enable" && !world.whitelist){
        world.whitelist = []
        sendPlayers({
          type:"error",
          data:"Whitelist has been enabled. You can rejoin if whitelisted.",
        })
        closePlayers()
      }else if(data.data === "disable" && world.whitelist) world.whitelist = null
      else if(data.data === "add" && !world.whitelist.includes(data.who)){
        world.whitelist.push(data.who)
      }else if(data.data === "remove" && world.whitelist.includes(data.who)){
        world.whitelist.splice(world.whitelist.indexOf(data.who), 1)
      }
    }else if(data.type === "fetchUsers"){
      var str = world.players.length + " players online: "
      world.players.forEach(u => str += u.username+", ")
      str = str.slice(0,str.length-2)

      var bannedLength = 0
      for(var b in world.banned) bannedLength ++
      if(bannedLength){
        str += "<br>"
        str += bannedLength + " people banned: "
        for(var b in world.banned) str += b + ", "
        str = str.slice(0,str.length-2)
      }
      if(world.whitelist && world.whitelist.length){
        str += "<br>"
        str += world.whitelist.length + " people whitelisted: "
        world.whitelist.forEach(u => str += u + ", ")
        str = str.slice(0,str.length-2)
      }
      
      sendPlayer(JSON.stringify({
        type:"message",
        username:"Server",
        data:str,
        fromServer:true
      }), data.FROM)
    }else if(data.type === "eval"){
      if(connection.isAdmin){
        var o = JSON.stringify({type:"eval",data:data.data})
        if(data.TO === "@A"){
          sendAllPlayers(o)
        }else if(data.TO){
          sendPlayerName(o, data.TO)
        }else{
          sendPlayers(o)
          console.log("all")
        }
        console.log(o,data)
        sendPlayer(JSON.stringify({
          type:"message",
          username:"Server",
          data:"Eval data sent",
          fromServer:true
        }), data.FROM)
      }else{
        sendPlayer(JSON.stringify({
          type:"message",
          username:"Server",
          data:"You can not use this command.",
          fromServer:true
        }), data.FROM)
      }
    }
  });
  connection.on('close', function(reasonCode, description) {
    if(reasonCode !== 1000 && reasonCode !== 1001){
      Log("Websocket closed with code: "+reasonCode+", "+description)
    }
    var idx = world.players.indexOf(connection)
    if(connection === world.host){
      var name = world.name
      var playerAmount = world.players.length
      sendPlayers(JSON.stringify({
        type:"error",
        data: "Server closed"
      }))
      closePlayers()
      worlds.splice(worlds.indexOf(world), 1)
      world = {}
      Log("MineKhan: "+username+" closed server: "+name+" with "+playerAmount+" people", worlds.length+" worlds")
    }else{
      sendPlayers(JSON.stringify({
        type:"dc",
        data: world.players[idx].id
      }))
      sendPlayers(JSON.stringify({
        type:"message",
        data: world.players[idx].username+" left. "+(world.players.length-1)+" players now.",
        username: "Server",
        fromServer:true
      }))
      Log("MineKhan: "+world.players[idx].username+" left the server: "+world.name)
      world.players.splice(idx, 1)
    }
    worldsChanged()
  });
  connection.on("error", function(err){
    console.log("UH OH!!! Websocket error", err)
  })
  worldsChanged()
};
function worldsChanged(){
  sendWorlds()
}

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

var worldsWs = new WebSocketRoom("/worlds")
worldsWs.onrequest = function(request,connection){
  connection.sendUTF(JSON.stringify(worlds.toRes()))
  connection.on("message",function(message){
    var data = message.utf8Data
    if(data === "get"){
      connection.sendUTF(JSON.stringify(worlds.toRes()))
    }
  })
}
function sendWorlds(){
  var str = JSON.stringify(worlds.toRes())
  for(var i=0; i<worldsWs.connections.length; i++){
    var con = worldsWs.connections[i]
    con.sendUTF(str)
  }
}

//console.clear()

void 0 //don't log stuff