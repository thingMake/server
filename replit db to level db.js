const Database = require("@replit/database");
const db = new Database()
const db2 = require("./db.js")

var f = async function(){
  var o = {raw:true}
  var k = await db.list()
  var l = k.length
  var i = 1244
  async function next(){
    var n = k[i]
    try{
      var v = await db.get(n, o)
      await db2.set(n, v, o)
    }catch{
      console.log("skipped",n)
    }
    i++
    console.log(i,"keys moved")
    if(i < l){
      setTimeout(next, 10)
    }
  }
  next()
}
f()