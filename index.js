/*
Useful functions:
LogAllOut, promoteToAdmin, deleteAccount, banFromMineKhan, unbanFromMineKhan
*/

//Variables
let multiplayerOn = true;
const multiplayerMsg = "No, No!"; //message when multiplayer is off

const express = require('express');
const app = express();
const cookieParser = require('cookie-parser');
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
const db2 = require("./db.js")
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

let log = [];
async function Log() {
  const data = [];
  for (let i = 0; i < arguments.length; i++) {
    data.push(arguments[i]);
  }
  console.log(...data);
  //let log = await db.get("log");
  //log = log || [];
  log.push(data);
  await db.set("log", log);
}

function clearLog() {
  db.delete("log").then(() => {
    console.clear();
    log = [];
  })
}
console.clear();
db.get("log").then(r => {
  r.forEach(v => {
    console.log(...v)
  })
  log = r;
}).catch(() => {});

let bannedFromMineKhan;
db.get("bannedFromMineKhan").then(r => {
  if (r) {
    bannedFromMineKhan = r;
    console.log("People banned from MineKhan: " + r.join(", "));
  } else {
    bannedFromMineKhan = [];
  }
})

function banFromMineKhan(who) {
  db.get("user:" + who).then(r => {
    if (!r) {
      return console.log(who + " doesn't exsist");
    }
    bannedFromMineKhan.push(who);
    if (r.ip) {
      bannedFromMineKhan.push(...r.ip);
    }
    db.set("bannedFromMineKhan", bannedFromMineKhan).then(() => console.log("done"));
  })
}

function unbanFromMineKhan(who) {
  const i = bannedFromMineKhan.indexOf(who);
  if (i === -1) {
    return console.log(who + " is not on the banned list");
  }
  bannedFromMineKhan.splice(i, 1);
  db.get("user:" + who).then(r => {
    if (r.ip) {
      for (let j = 0; j < r.ip.length; j++) {
        const i = bannedFromMineKhan.indexOf(r.ip[j]);
        if (i === -1) {
          console.log(who + " is not on the banned list");
        } else {
          bannedFromMineKhan.splice(i, 1);
        }
      }
    }
    db.set("bannedFromMineKhan", bannedFromMineKhan).then(() => console.log("done"));
  })
}

/*let id = 0xf
function generateId() {
  id += Math.floor(Math.random() * 10)
  return id.toString(64)
}*/
//var genid = 0
// consider using crypto.randomUUID();
function generateId() {
  //genid ++
  //return genid
  return Date.now();
}

function valueToString(v, nf) { //for log
  let str = "";
  if (typeof v === "function") {
    str = "<span style='color:purple;'>"+v.toString()+"</span>";
  } else if (Array.isArray(v)) {
    str = "<span style='color:red;'>[";
    for (let i = 0; i < v.length; i++) {
      str += valueToString(v[i], true) + ", ";
    }
    if (v.length) str = str.substring(0, str.length - 2); //remove trailing ", "
    str += "]</span>";
  } else if (typeof v === "object") {
    str = "<span style='color:red;'>{";
    let hasTrailing;
    for (const [key, value] of Object.enteries(v)){
      str += "<span style='color:blue;'>" + key + "</span>: " + valueToString(value, true) + ", ";
      hasTrailing = true;
    }
    if (hasTrailing) str = str.substring(0, str.length - 2); //remove trailing ", "
    str += "}</span>";
  } else if (typeof v === "number") {
    str = "<span style='color:orange;'>"+v.toString()+"</span>";
  } else if (typeof v === "string") {
    if (v.startsWith("MineKhan")) {
      v = v.replace("MineKhan","<span style='background:yellow;'>MineKhan</span>");
    }
    if (v.startsWith("New comment")) {
      v = v.replace("comment","<span style='background:orange;'>comment</span>");
    }
    if (v.startsWith("New post")) {
      v = v.replace("post","<span style='background:orange;'>post</span>");
    }

    v = v.replace(/(changed their bio|changed their skin)/, "<span style='background:lightgreen;'>$1</span>")
    
    v = v.replace(/%>/g, "<b style='color:orange; margin-right:15px;'>&gt;</b>");
    v = v.replace(/%</g, "<b style='color:orange; margin-right:15px;'>&nbsp;</b>"); //⋖
    if (nf) {
      str = "<span style='color:green;'>'" + v + "'</span>";
    } else {
      str = v;
    }
  } else str = v;
  return str;
}

router.get('/', function(req, res) {
  res.sendFile(path.join(__dirname, "/info.html"));
});

router.get('/test', function (req, res) {
  res.send("test");
});
router.get('/log', async (req, res) => {
  const options = url.parse(req.url, true).query;
  const log = await db.get("log");
  if (!log) {
    return res.send("Empty");
  }
  let str = "<style>#logContent>span{max-width:100%;text-overflow:ellipsis;white-space:nowrap;display:inline-block;overflow:hidden;}</style><div id='logContent' style='font-family:monospace;'>";
  log.forEach(v => {
    if (options.nominekhan && v[0].startsWith("MineKhan: ")) {
      return;
    }
    str += "<span>";
    v.forEach(r => {
      str += valueToString(r) + " ";
    });
    str += "</span><br>";
  });
  str += "</div>";
  str += "<br><br>";
  str += "People banned from MineKhan: " + bannedFromMineKhan.join(", ");
  res.send(str);
});
/*router.get("/pfp.png", (req, res) => {
  res.sendFile(__dirname + "/pfp.png")
})*/
router.get("/panorama", (req, res) => {
  res.redirect("https://data.thingmaker.repl.co/images/panorama/2022.png");
});

app.use(express.static('public'))

function getPostData(req){
  return new Promise(function(resolve) {
    let body = '';
    req.on('data', chunk => {
      body += chunk.toString(); // convert Buffer to string
    });
    req.on('end', () => {
      body = JSON.parse(body);
      req.body = body;
      resolve(body);
    });
  })
}
function getPostText(req){
  return new Promise(function(resolve) {
    let body = '';
    req.on('data', chunk => {
      body += chunk.toString(); // convert Buffer to string
    });
    req.on('end', () => {
      req.body = body;
      resolve(body);
    });
  })
}
//cookies to see if you logged in
function setUser(sid, res) {
  return res.cookie("sid", sid, {
    maxAge: 4000000000,
    path: "/",
    domain: ".thingmaker.repl.co"
  });
}
function logout(request, res){
  return new Promise(async (resolve, reject) => {
    const sid = request.cookies.sid;
    /*res.cookie("sid", "", {
      maxAge: 0,
      path: "/",
      domain: ".thingmaker.repl.co"
    });*/
    res.clearCookie("sid",{
      maxAge: 0,
      path: "/",
      domain: ".thingmaker.repl.co"
    });
    await db.delete("session:" + sid).then(() => {
      resolve();
    }).catch(e => {
      Log(e);
    });
  })
}

async function validate(request, response, next) {
  const sid = request.cookies ? request.cookies.sid : null;
  if (sid) {
    await db.get("session:" + sid)
      .then(async (result) => {
        if (!result) {
          return;
        }
        request.username = result.username
        db.get("user:" +  request.username).then(u => {
          if (u) {
            u.ip = u.ip || []
            if (request.clientIp && !u.ip.includes(request.clientIp)) {
              u.ip.push(request.clientIp)
            }
            db.set("user:" + request.username, u).then(() => {
              next();
            });
          } else {
            request.username = null;
            next();
          }
        })
      }).catch((e) => response.status(401).send(/*"Invalid session id"*/""));
  } else {
    /*response.status(401).send*///console.log("Not logged in")
    next();
  }
}

async function isAdmin(username) {
  let admin;
  await db.get("user:" + username).then(r => {
    admin = r.admin;
  }).catch(e => Log(e));
  return admin;
}
async function notif(data, username) {
  await db.get("user:" + username).then(async u => {
    u.notifs = u.notifs || [];
    u.notifs.push({
      notif: data,
      id: generateId(),
      read: false
    });
    await db.set("user:" + username, u).then(() => {});
  }).catch(e => Log(e));
}
function addNotif(data, u) {
  u.notifs = u.notifs || [];
  u.notifs.push({
    notif: data,
    id: generateId(),
    read: false
  });
}
/*router.get('/setuser', (req, res)=>{
  setUser("user", res)
  res.send('user data added to cookie');
});
app.use('/setuser', router);*/
router.get('/getuser', validate, (req, res) => {
  res.header("Content-Type", "text/plain");
  if (req.username) {
    res.send(req.username);
    return;
  }
  res.send("");
});

router.post("/register", async (request, response) => {
  await getPostData(request);

  if (!request.body.password) {
    return response.status(401).json({
      success: false,
      "message": "A `password` is required"
    });
  } else if (!request.body.username) {
    return response.status(401).json({
      success: false,
      "message": "A `username` is required"
    });
  } else if (request.body.username.length > 15) {
    return response.json({
      success: false,
      message: "Username can only have less than 15 characters."
    })
  }

  if (request.body.username.match(/[^a-zA-Z0-9\-_]/)) {
    return response.json({ message: "Username can only contain characters: A-Z, a-z, 0-9, - and _" });
  }

  let exsists = false;
  await db.get("user:" + request.body.username).then(u => {
    if (u) {
      exsists = true
      response.status(401).json({
        success: false,
        message: "Account already exsists"
      });
    }
  }).catch(() => exsists = false);
  if (exsists) {
    return;
  }

  const id = generateId();
  const account = {
    "type": "account",
    "pid": id,
    "username": request.body.username,
    "password": bcrypt.hashSync(request.body.password, 10),
    email:request.body.email,
    pfp: "https://server.thingmaker.repl.co/pfp.png",
    timestamp: Date.now(),
  };  
  db.set("user:"+account.username, account).then(() => {
    const session = {
        "type": "session",
        "id": generateId(),
        "pid": account.pid,
        "username": account.username
    }
    db.set("session:" + session.id, session)
        .then(() => {
          setUser(session.id, response);
          response.json({
            success:true,
            redirect:"/website/website.html"
          });
          Log("New user", account.username);
        })
        .catch(e => response.status(500).send({success:false, message:e}));
  }).catch(e => response.status(500).send({success:false, message:e}));
})

router.post('/login', async (request, response) => {
  await getPostData(request);
  if (!request.body.username) {
    return response.status(401).send({ success: false, message: "A `username` is required" });
  } else if (!request.body.password) {
    return response.status(401).send({ success: false, message: "A `password` is required" });
  }
  
  await db.get("user:" + request.body.username)
    .then(async (result) => {
      if (!bcrypt.compareSync(request.body.password, result.password)) {
        return response.status(500).send({ success: false, message: "Password invalid" });
      }
      const session = {
        "type": "session",
        "id": generateId(),
        "pid": result.pid,
        "username": result.username
      };
      await db.set("session:" + session.id, session)
        .then(() => {
          setUser(session.id, response)
          response.json({
            success:true,
            redirect:"/website/website.html"
          });
        }).catch(e => response.status(500).send({success:false, message:e}));
    }).catch(e => response.status(500).send(e));
});
router.get("/account", validate, async (request, response) => {
  if(!request.username) return response.status(401).send('"Unauthorized"');
  try {
    await db.get("user:"+request.username)
      .then((result) => response.json(result))
      .catch((e) => response.status(500).send('"' + e + '"'));
  } catch (e) {
    console.error(e.message);
    response.status(500).send('"' + e + '"');
  }
})
//delete account
router.delete("/deleteAccount", validate, async (request, response) => {
  try {
    await logout(request, response)
    await db.delete("user:"+request.username)
      .then(() => {
        response.send("deleted");
        Log("Deleted user", request.username);
      })
      .catch((e) => response.status(500).send(e));
  } catch (e) {
    console.error(e.message);
  }
})
router.get("/logout", async (request, response) => {
  await logout(request, response);
  response.send("Your'e logged out");
})
router.get("/account/*", async (request, response) => {
  let username = request.url.split("/").pop();
  try {
    await db.get("user:"+username)
      .then((result) => response.json(result))
      .catch((e) => response.status(500).send(e))
  } catch (e) {
    console.error(e.message);
  }
})
router.post("/changePfp", validate, async(req, res) => {
  if(!req.username) return res.json({ message:"Unauthorized" });
  await getPostData(req);
  await db.get("user:" + req.username).then(r => {
    if(req.body.pfp) r.pfp = req.body.pfp
    if(req.body.bg) r.bg = req.body.bg
    db.set("user:" + req.username, r).then(() => {
      res.json({ success: true, pfp: req.body.pfp, bg: req.body.bg })
    }).catch(e => res.json({ message: e }))
  }).catch(e => res.json({ message: e }))
})
router.post("/changePwd", validate, async(req, res) => {
  if(!req.username) return res.json({ message: "Unauthorized" })
  await getPostData(req)
  db.get("user:" + req.username).then(r => {
    r.password = bcrypt.hashSync(req.body.pwd, 10);
    db.set("user:" + req.username, r).then(() => {
      res.json({ success: true })
    }).catch(e => res.json({ message: e }))
  }).catch(e => res.json({ message: e }))
  Log(req.username + " changed their password")
})
router.post("/changeEmail", validate, async(req, res) => {
  if(!req.username) return res.json({ message:"Unauthorized" });
  await getPostData(req);
  db.get("user:" + req.username).then(r => {
    r.email = req.body.email;
    db.set("user:" + req.username, r).then(() => {
      res.json({ success: true });
    }).catch(e => res.json({ message: e }));
  }).catch(e => res.json({ message: e }));
  Log(req.username+" changed their email");
});
router.post("/changeBio", validate, async (req, res) => {
  if (!req.username) return res.status(401).json({ message: "Unauthorized" });
  await getPostData(req);
  db.get("user:" + req.username).then(r => {
    r.bio = req.body.bio;
    db.set("user:" + req.username, r).then(() => {
      res.json({ success: true });
      Log(req.username + " changed their bio.");
    }).catch(e => res.json({ message: e }));
  }).catch(e => res.json({ message: e }));
})

router.post("/changeSkin", validate, async (req, res) => {
  if (!req.username) return res.status(401).json({ message: "Unauthorized" })
  await getPostData(req);
  if (!req.body.skin) return res.json({ message: "Please set a skin" });
  db.get("user:" + req.username).then(r => {
    r.skin = req.body.skin;
    db.set("user:" + req.username, r).then(() => {
      res.json({ success: true });
      Log(req.username + " changed their skin.");
    }).catch(e => res.json({ message: e }));
  }).catch(e => res.json({ message: e }));
});

router.get("/deleteNotifs", validate, (req,res) => {
  if (!req.username) return res.status(401).json({ message: "Unathorized" });
  db.get("user:" + req.username).then(r => {
    delete r.notifs;
    db.set("user:" + req.username, r).then(() => {
      res.json({ success: true });
      Log(req.username + " deleted their notifications.");
    }).catch(e => res.json({ message: e }));
  }).catch(e => res.json({ message: e }));
})
router.get("/pfp/*", async(req, res) => {
  let username = req.url.split("/").pop();
  db.get("user:" + username).then(d => {
    /*fetch(d.pfp, (err,meta,body) => {
      if(err){
        console.log(err)
        return res.send("error")
      }
      res.send(body)
    })*/
    res.redirect(d.pfp);
  }).catch(() => res.send("error"))
})
router.get("/skin/*", async (req, res) => {
  let username = req.url.split("/").pop();
  db.get("user:"+username).then(d => {
    const data = d.skin.replace(/^data:image\/png;base64,/, '');
    const img = Buffer.from(data, 'base64');
    res.writeHead(200, {
      'Content-Type': 'image/png',
      'Content-Length': img.length
    });
    res.end(img);
  }).catch(() => res.send("error"));
});
router.get("/users", (req, res) => {
  db.list("user:").then((users) => { res.json(users) });
});

const currentMedia = {
  type: "",
  data: ""
};
router.get("/currentMedia", async (req, res) => {
  if (currentMedia.data) {
    res.header("Content-Type", currentMedia.type);
    res.end(currentMedia.data);
  } else res.send("");
})
router.post("/newMedia", async (req, res) => {
  await getPostText(req);
  const id = generateId();
  /*let buffer = Buffer.from(req.body)
  let prefix = `data:${req.headers['content-type']};base64,`
  let url = prefix + buffer.toString("base64").replace(/(\r\n|\n|\r)/gm,"")
  console.log(prefix)*/
  currentMedia.type = req.headers['content-type'];
  currentMedia.data = Buffer.from(req.body, "base64");

  cloudinary.uploader.upload("https://server.thingmaker.repl.co/currentMedia", {
    public_id: id,
    resource_type: currentMedia.type.split("/")[0]
  }, function(error, result){
    if (error){
      Log(error);
      return res.json({ message: error });
    }
    res.json({ success: true, url: result.secure_url });
    Log("Media id:", id);
  })
})
// user makes a post/blog
router.post("/post", validate, async (request, response) => {
  if (!request.username){
    return response.status(401).json({ message: "You need to login to create posts. Login is at the top right." })
  }
  await getPostData(request);
  if (!request.body.title) {
    return response.status(401).json({ "message": "A `title` is required" });
  } else if (!request.body.content) {
    return response.status(401).json({ "message": "A `content` is required" });
  }
  const uniqueId = generateId();
  let blog = {
    "type": "blog",
    "username": request.username,
    id: uniqueId,
    "title": request.body.title,
    "content": request.body.content,
    "followers": [request.username],
    "timestamp": Date.now()
  };
  db.set("post:" + uniqueId, blog)
    .then(() => {
      response.json({
        success: true,
        data: blog,
        redirect: "/website/post.html?id=" + uniqueId
      })
      Log("New post", blog.title);
    })
    .catch((e) => response.status(500).json({ message: e }));
})
router.delete("/deletePost/*", validate, async(req, res) => {
  let id = req.url.split("/").pop();
  let canDelete = false;
  let adminDelete = false;
  let title;
  let author;
  await db.get("post:" + id).then(async r => {
    title = r.title;
    author = r.username;
    if (req.username === r.username){
      canDelete = true;
    } else {
      await db.get("user:" + req.username).then(u => {
        if (u.admin) {
          canDelete = true;
          adminDelete = true;
        }
      }).catch(() => res.send("error"));
    }
  }).catch(() => res.send("error"));

  if (!canDelete) return res.status(401).send("You're not authorized");
  db.delete("post:" + id).then(async() => {
    if (adminDelete) await notif(req.username + " deleted your post: " + title, author);
    res.send("ok");
    Log("Deleted post", title)
  }).catch(e => {res.send("error"); console.log(e)})
})
//get a post by its id
router.get("/post/*", (request, res) => {
  let id = request.url.split("/").pop()
  db.get("post:" + id).then(data => {
    res.json(data)
  }).catch(() => res.send(null))
})
//get posts from a user
router.get("/posts/*", (req, res) => {
  let username = req.url.split("/").pop();
  db.list("post:").then(async matches => {
    const posts = [];
    for (let i = 0; i < matches.length; i++){
      await db.get(matches[i]).then(r => {
        if (r.username === username){
          posts.push({
            username:r.username,
            id:r.id,
            title:r.title,
            timestamp:r.timestamp
          });
        }
      })
    }
    res.json(posts);
  }).catch(() => res.send(null));
});
router.get("/posts", (req, res) => {
  db.list("post:").then(async matches => {
    let posts = []
    for (let i = 0; i < matches.length; i++){
      await db.get(matches[i]).then(r => {
        posts.push({
          username:r.username,
          id:r.id,
          title:r.title,
          timestamp:r.timestamp
        });
      });
    }
    res.json(posts)
  }).catch(() => res.send(null));
});
router.post("/commentPost/*", validate, async (req, res) => {
  if (!req.username) return res.json({ message: "Sign in to comment" });
  let id = req.url.split("/").pop();
  await getPostData(req);
  if (!req.body.comment) {
    return res.json({ message: "Comment cannot be blank." });
  }

  //get post and add comment and replace post
  //first comment on top
  let pfp;
  await db.get("user:" + req.username).then(r => {
    pfp = r.pfp;
  }).catch(e => res.json({ message: e }));
  await db.get("post:"+id).then(async r => {
    const cid = generateId();
    r.comments = r.comments || [];
    let commentData = {
      username:req.username,
      //pfp:pfp,
      comment:req.body.comment,
      id: cid,
      timestamp:Date.now()
    }
    r.comments.push(commentData)
    if (r.followers) {
      for (let i = 0; i < r.followers.length; i++) {
        if (r.followers[i] !== req.username) {
          await db.get("user:" + r.followers[i]).then(async u => {
            if (!u) {
              const who = r.followers[i];
              Log(`${who} doesn't exsist but is following ${r.title}`)
              r.followers.splice(i, 1)
              i --
              Log(`Removed ${who} from following ${r.title}`);
              return
            }
            u.notifs = u.notifs || [];
            u.notifs.push({
              notif: `req.username+" commented at <a href='/website/post.html?id="+id#comment${cid}">${r.title}</a>`,
              id: generateId(),
              read: false
            });
            await db.set("user:" + r.followers[i], u).then(() => {});
          }).catch(e => Log(e));
        }
      }
    }
    db.set("post:" + id, r).then(() => {
      res.json({success: true, id: cid})
      sendPostWs({
        type: "comment",
        data: commentData
      }, id, req.body.userId)
      Log("New comment at", r.title);
    });
  }).catch(() => {
    res.json({message: "Post doesn't exsist"})
  });
});
router.post("/deletePostComment/*", validate, async (req, res) => {
  if (!req.username) return res.status(401).send("error");
  let id = req.url.split("/").pop();
  await getPostData(req);
  db.get("post:" + id).then(async d => {
    let canDelete, sendNotif;
    let cid = req.body.cid;
    let c
    for (let i = 0; i < d.comments.length; i++){
      if (d.comments[i].id === cid) {
        c = d.comments[i];
        break;
      }
    }
    if (c.username === req.username) {//creator of comment delete the comment
      canDelete = true;
    } else if (req.username === d.username) {//creator of post delete the comment
      sendNotif = canDelete = true;
    } else {//admin delete comment
      await db.get("user:" + req.username).then(r => {
        if (r.admin) sendNotif = canDelete = true;
      });
    }
    if ((!c) || (!canDelete)) return res.send("error");
    c.hide = true;
    db.set("post:" + id, d).then(async () => {
      res.send("ok");
      if(sendNotif) await notif(req.username + " deleted your comment at: " + d.title, c.username);
      sendPostWs({
        type:"deleteComment",
        data: cid
      }, id, req.body.userId);
      Log("Deleted comment at", d.title);
    });
  });
});
router.post("/followPost/*", validate, async (req, res) => {
  if (!req.username) return res.status(401).send("error")
  let id = req.url.split("/").pop();
  await getPostData(req);
  db.get("post:" + id).then(r => {
    let f = r.followers || (r.followers = []);
    if (req.body.follow) {
      if (!f.includes(req.username)) {
        f.push(req.username);
      }
    } else {
      const i = f.indexOf(req.username);
      if(i > -1){
        f.splice(i, 1);
      }
    }
    db.set("post:" + id, r).then(() => res.send("ok"));
  }).catch(() => {res.send("error")});
});
router.get("/comments/*", (req, res) => {
  let id = req.url.split("/").pop();
  db.get("post:" + id).then(r => {
    res.json(r.comments || []);
  }).catch(() => {res.send(null)});
});
router.get("/clearNotifs", validate, (req, res) => {
  if (!req.username) return res.status(401).send("Unauthorized");
  db.get("user:" + req.username).then(r => {
    for (let i = 0; i < r.notifs.length; i++){
      const n = r.notifs[i];
      n.read = true;
    }
    db.set("user:" + req.username, r).then(() => res.send("cleared")).catch(e => Log(e));
  }).catch(e => Log(e));
});

router.post("/resetPwd", async (req, res) => {
  return res.json({ message: "Functionality not available yet" })

  await getPostData(req);
  const username = req.body.username;
  db.get("user:" + username).then(r => {
    if (!r) return res.json({ message: "That account doesn;t exsist." });
    let email = r.email || "";
    if (!email) {
      return res.json({ message: "Sorry, that account doesn't have an email." })
    }
    let transport = nodemailer.createTransport({
      host: "smtp.gmail.com",
      port: 2525,
      auth: {
        user: "aarontao950@gmail.com",
        pass: process.env['gmail_pass']
      }
    });
    let message = {
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
    };
    transport.sendMail(message, function (err, info) {
      if (err) {
        res.json({ message: JSON.stringify(err) })
      } else {
        Log("Reset password email sent to " + req.username,info);
        res.json({ success: true });
      }
    });
  });
});

router.get("/sessions", (req, res) => {
  const pwd = process.env['pwd'];
  let urlData = url.parse(req.url, true);
  let q = urlData.query.pwd
  if (q === pwd) {
    db.list("session:").then((d) => {res.json(d)})
  } else {
    res.sendFile(__dirname + "/401.html");
  }
})

//for minekhan
router.get("/worlds", (req, res) => {
  let data = []
  for (let i = 0; i < worlds.length; i++){
    let w = worlds[i];
    data.push({
      name: w.name,
      players: (() => {
        let ps = [];
        w.players.forEach(r => ps.push(r.username));
        return ps;
      })(),
      id: w.id,
      host: w.host.username
    })
  }
  res.json(data);
})
router.get("/worldsPing", (req, res) => {
  let w = [];
  for(let i = 0; i < worlds.length; i++){
    const world = worlds[i];
    w.push(pingWorld(world.id));
  }
  Promise.all(w).then(w => {
    let data = {}
    for(let i = 0; i < w.length; i++){
      data[worlds[i].id] = w[i];
    }
    res.json(data);
  })
})

router.post("/admin/messageUser/*", validate, async (req, res) => {
  if (!await isAdmin(req.username)) return res.json({ message:"Unauthorized" })
  await getPostData(req);
  let to = req.url.split("/").pop();
  await notif(req.body.message, to);
  res.json({ success: true });
})
app.use(router);

//404
app.use(function(req, res, next) {
  res.status(404);
  res.sendFile(__dirname + '/404.html');
});

let serverPort = app.listen(3000, function() {
  console.log("App server is running on port 3000");
});

function LogAllOut(){
  db.list("session:").then(m => {
    const p = []
    for(let i = 0; i < m.length; i++){
      p.push(db.delete(m[i]))
    }
    Promise.all(p).then(() => {
      console.log("Done")
    })
  })
}
function deleteAccount(username){
  db.delete("user:" + username).then(() => console.log("done"))
}
function promoteToAdmin(username){
  db.get("user:" + username).then(r =>{
    if(!r) return console.log("user doesn't exsist")
    r.admin = true
    addNotif("You have been promoted to admin", r)
    db.set("user:" + username, r).then(() => console.log("done"))
  })
}

//WebSocket
class WebSocketRoom {
  constructor(path) {
    this.path = path
    this.onrequest = null
    this.connections = []
    this.validateFunc = null

    WebSocketRoom.rooms.push(this)
  }
  static getRoom(path){
    for(let i = 0; i < this.rooms.length; i++){
      if(this.rooms[i].path === path){
        return this.rooms[i]
      }
    }
  }
  static async connection(request) {
    let urlData = url.parse(request.httpRequest.url, true);
    let path = urlData.pathname;
    const room = this.getRoom(path);
    if (room) {
      let valid = true;
      const options = { send: null };
      if (room.validateFunc) {
        valid = await room.validateFunc(request, options);
      }
      const connection = request.accept(null, request.origin);
      if (options.send) {
        connection.sendUTF(options.send);
      }
      if (!valid) {
        return connection.close();
      }
      room.connections.push(connection);
      room.onrequest(request, connection, urlData);
      connection.on("close", function () {
        const idx = room.connections.indexOf(connection);
        room.connections.splice(idx, 1);
      })
    }
  }
}
WebSocketRoom.rooms = []
const wsServer = new WebSocketServer({
  httpServer: serverPort
})
wsServer.on("request", req => WebSocketRoom.connection(req))

//client side: let ws = new WebSocket("wss://server.thingmaker.repl.co/ws")
const minekhanWs = new WebSocketRoom("/ws");

//Function to validate request
minekhanWs.validateFunc = async (request, options) => {
  if (!multiplayerOn) {
    options.send = JSON.stringify({
      type: "error",
      data: multiplayerMsg
    });
    return false;
  }

  if (request.origin !== "https://minekhan.thingmaker.repl.co") {
    return false;
  }
  const ip = requestIp.getClientIp(request);
  if (bannedFromMineKhan.includes(ip)) {
    return false;
  }

  let sid;
  for (let i = 0; i < request.cookies.length; i++) {
    const c = request.cookies[i];
    if (c.name === "sid") {
      sid = c.value;
      break;
    }
  }
  if (sid) {
    return await db.get("session:" + sid)
      .then(async result => {
        if (await db.get("user:" + result.username).then(u => {
          if (u) {
            request.isAdmin = u.admin || false;
          } else {
            return true;
          }
        })) {
          return false;
        }
        return result.username;
      })
  }
  return false;
}

const worlds = [];
worlds.find = (id) => {
  for (let i = 0; i < worlds.length; i++){
    if (worlds[i].id === id){
      return worlds[i];
    }
  }
}
worlds.pings = {}
async function pingWorld(id){
  const w = worlds.find(id)
  if (!w) {
    return "error";
  }
  const start = Date.now()
  const ms = await new Promise((resolve, reject) => {
    let resolved = false;
    worlds.pings[id] = {
      id: id,
      done: f => {
        const finish = Date.now();
        const ms = (finish - start);
        resolve(ms);
        resolved = true;
      }
    };
    w.host.sendUTF(JSON.stringify({
      type: "ping"
    }))
    setTimeout(() => {
      if (!resolved) {
        resolve("timeout");
      }
    }, 20000);
  });
  return ms;
}

worlds.sendEval = function (index, player, data) {
  Log(`%>worlds[${index}].players[${player}].sendUTF('{"type":"eval","data":"${data}"}')`);
  const world = worlds[index];
  if (!world) {
    return Log("%<Error: worlds["+index+"] is not defined");
  }
  if (player === "@a") {
    world.players.forEach(p => {
      p.sendUTF(JSON.stringify({ type: "eval", data: data }));
    })
  } else {
    const p = world.players[player];
    if (!p) {
      return Log("%<Error: worlds["+index+"].players["+player+"] is not defined");
    }
    p.sendUTF(JSON.stringify({ type: "eval", data: data }));
    Log("%<Eval data sent.");
  }
  Log("%<Eval data sent.");
}

minekhanWs.onrequest = function (request, connection, urlData) {
  const queryObject = urlData.query;
  let target = queryObject.target;
  if(!(target || target === 0)){
    connection.close();
    return
  }
  
  Log("MineKhan: Client connected: ", queryObject)
  connection.isAdmin = request.isAdmin

  //add user to a world
  let world = worlds.find(target)
  if (world) {
    world.players.push(connection)
  } else {
    world = {
      id: target,
      players: [connection],
      host: connection,
      name: "Ghost server "+target
    }
    worlds.push(world)
  }
  function sendPlayers(msg) {
    for (let i = 0; i < world.players.length; i++) {
      let p = world.players[i];
      if (p !== connection) {
        p.sendUTF(msg);
      }
    }
  }
  function sendAllPlayers(msg) {
    for (let i = 0; i < world.players.length; i++) {
      const p = world.players[i];
      p.sendUTF(msg);
    }
  }
  function sendPlayer(msg, to) {
    for (let i = 0; i < world.players.length; i++) {
      const p = world.players[i];
      if (p.id === to) {
        p.sendUTF(msg);
      }
    }
  }
  function sendThisPlayer(msg) {
    connection.sendUTF(msg);
  }
  function sendPlayerName(msg, to) {
    for (let i = 0; i < world.players.length; i++) {
      let p = world.players[i];
      if (p.username === to) {
        p.sendUTF(msg);
      }
    }
  }
  function closePlayers() {
    for (let i = 0; i < world.players.length; i++) {
      const p = world.players[i];
      if (p !== connection) {
        p.close();
      }
    }
  }
  function closePlayer(id) {
    for (let i = 0; i < world.players.length; i++) {
      const p = world.players[i];
      if (p.username === id) {
        p.close();
      }
    }
  }
  function findPlayer(id){
    for (let i = 0; i < world.players.length; i++) {
      const p = world.players[i];
      if (p.username === id) {
        return p;
      }
    }
  }
  connection.on('message', function (message) {
    let data = JSON.parse(message.utf8Data);
    if (data.type === "connect") {
      if (bannedFromMineKhan.includes(data.username)) {
        sendThisPlayer(JSON.stringify({
          type: "error",
          data: "You are banned from MineKhan."
        }))
        connection.close();
        return;
      }

      connection.id = data.id;
      connection.username = data.username;
      sendPlayers(JSON.stringify({
        type: "message",
        data: `${data.username} is connecting. ${world.players.length} players now.`,
        username: "Server",
        fromServer:true
      }));
      Log(`MineKhan: ${data.username} joined the server: ${world.name}`)
    } else if (data.type === "joined") {
      sendPlayers(JSON.stringify({
        type: "message",
        data: data.username + " joined. ",
        username: "Server",
        fromServer: true
      }));
    } else if (data.type === "init") {
      world.name = data.name;
      Log("MineKhan: Server opened: " + world.name, worlds.length + " worlds");
    } else if (data.type === "pong") {
      const p = worlds.pings[world.id];
      if (p) {
        p.done(data.data);
      }
     }else if(data.type === "pos" || data.type === "setBlock" || data.type === "getSave" || data.type === "message" || data.type === "entityPos" || data.type === "entityPosAll" || data.type === "entityDelete" || data.type === "die" || data.type === "harmEffect" || data.type === "achievment" ||  data.type === "playSound" || data.type === "mySkin" || data.type === "setTags") {
      sendPlayers(message.utf8Data)
    } else if (data.type === "loadSave" || data.type === "hit") {
      sendPlayer(message.utf8Data, data.TO)
    } else if (data.type === "kill") {
      if (data.data === "@a") {
        sendPlayers(JSON.stringify({ type: "kill", data: data.message }))
      } else {
        sendPlayerName(JSON.stringify({
          type: "kill",
          data: data.message
        }), data.data);
      }
    } else if (data.type === "diamondsToYou") {
      sendPlayer(JSON.stringify({
        type:"diamondsToYou"
      }), data.TO);
    } else if (data.type === "ban") {
      const banWho = findPlayer(data.data);
      if (banWho && banWho.isAdmin) {
        sendPlayer(JSON.stringify({
          type: "message",
          username: "Server",
          data: "You can't ban " + data.data,
          fromServer: true
        }), data.FROM);
        sendPlayers(JSON.stringify({
          type: "message",
          username: "Server",
          data: `The host tried to ban ${data.data}.`,
          fromServer: true
        }));
        return;
      }
      sendPlayerName(JSON.stringify({
        type: "error",
        data: data.reason ? "You've been banned from this world.\n\nReason:\n" + data.reason : "You've been banned from this world."
      }), data.data)
      sendPlayers(JSON.stringify({
        type: "message",
        username: "Server",
        data: data.data + " got banned.",
        fromServer: true
      }));
      Log(`MineKhan: ${data.data} got banned from the server: ${world.name}`);
      closePlayer(data.data);
    } else if (data.type === "fetchUsers") {
      let arr = [];
      world.players.forEach(u => {
        arr.push(u.username);
      });
      sendPlayer(JSON.stringify({
        type: "message",
        username: "Server",
        data: arr.join(", "),
        fromServer: true
      }), data.FROM);
    } else if(data.type === "eval") {
      if (connection === world.host || connection.isAdmin) {
        const o = JSON.stringify({ type: "eval", data: data.data });
        if (data.TO === "@A") {
          sendAllPlayers(o);
        } else if (data.TO) {
          sendPlayerName(o, data.TO);
        } else {
          sendPlayers(o);
          console.log("all");
        }
        console.log(o, data);
        sendPlayer(JSON.stringify({
          type: "message",
          username: "Server",
          data: "Eval data sent",
          fromServer: true
        }), data.FROM);
      } else {
        sendPlayer(JSON.stringify({
          type: "message",
          username: "Server",
          data: "Your not the host!!!",
          fromServer: true
        }), data.FROM);
      }
    }
  });
  connection.on('close', function(reasonCode, description) {
    const idx = world.players.indexOf(connection);
    if (connection === world.host) {
      const name = world.name;
      const playerAmount = world.players.length;
      sendPlayers(JSON.stringify({
        type: "error",
        data: "Server closed"
      }));
      closePlayers();
      worlds.splice(worlds.indexOf(world), 1);
      world = {};
      Log(`MineKhan: Server closed: ${name} with ${playerAmount} people ${worlds.length} worlds`);
    } else {
      sendPlayers(JSON.stringify({
        type: "dc",
        data: world.players[idx].id
      }));
      sendPlayers(JSON.stringify({
        type: "message",
        data: world.players[idx].username + " left. " + (world.players.length - 1) + " players now.",
        username: "Server",
        fromServer: true
      }));
      Log(`MineKhan: ${world.players[idx].username} left the server: ${world.name}`)
      world.players.splice(idx, 1)
    }
  });
  connection.on("error", function (err) {
    console.log("UH OH!!! Websocket error", err);
  });
};

let postWs = new WebSocketRoom("/postWs");
postWs.onrequest = function(req, connection, urlData){
  connection.postId = urlData.query.id;
  connection.on("message", function(message) {
    let packet = JSON.parse(message.utf8Data);
    if (packet.type === "connect") {
      connection.userId = packet.userId;
    }
  })
}
function sendPostWs(obj, id, fromUserId){
  let str = JSON.stringify(obj);
  for (let i = 0; i < postWs.connections.length; i++){
    let con = postWs.connections[i];
    if (con.postId === id && fromUserId !== con.userId) con.sendUTF(str)
  }
}

//console.clear()


void 0 //don't log stuff
