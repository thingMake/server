const level = require('level')

//Create our database, supply location and options.
//This will create or open the underlying store.
const db = level('my-db')

if (!db.supports.permanence) {
  throw new Error('Persistent storage is required')
}

  db.get('name', function (err, value) {
    if (err) return console.log('Ooops!', err) // likely the key was not found

    console.log('name=' + value)
  })

module.exports = {
  get:async function(key){
    var value = await db.get(key)
    if(value){
      return JSON.parse(value)
    }else{
      return null
    }
  },
  set:async function(key, value){
    await db.put(key, value)
    return this
  },
  delete:async function(key){
    await db.del(key)
    return this
  }
}