const level = require('level')

//Create our database, supply location and options.
//This will create or open the underlying store.
const db = level('my-db')

if (!db.supports.permanence) {
  throw new Error('Persistent storage is required')
}

/*db.get('name', function (err, value) {
  if (err) return console.log('Ooops!', err) // likely the key was not found

  console.log('name=' + value)
})*/

module.exports = {
  get:async function(key){
    var value = await db.get(key).catch(() => null)
    if(value){
      return JSON.parse(value)
    }else{
      return null
    }
  },
  set:async function(key, value, options){
    if(!(options && options.raw)) value = JSON.stringify(value)
    await db.put(key, value)
    return this
  },
  delete:async function(key){
    await db.del(key)
    return this
  },
  list:function(prefix, values){
    return new Promise(function(resolve, reject){
      var obj = values ? {} : []
      db.createReadStream()
      .on('data', function (data) {
        if(prefix && !data.key.startsWith(prefix)){
          return
        }
        if(values){
          obj[data.key] = JSON.parse(data.value)
        }else{
          obj.push(data.key)
        }
      })
      .on('error', function (err) {
        console.log('Oh my!', err)
        reject(err)
      })
      .on('close', function () {
        //console.log('Stream closed')
      })
      .on('end', function () {
        resolve(obj)
      })
    })
  }
}