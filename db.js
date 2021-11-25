const level = require('level')

//Create our database, supply location and options.
//This will create or open the underlying store.
const db = level('my-db')

if (!db.supports.permanence) {
  throw new Error('Persistent storage is required')
}

db.get('name', function (err, value) {
  if (err) {
    return console.log('Ooops!', err) // likely the key was not found
  }

  console.log('name=' + value);
})

module.exports = {
  async get(key) {
    const value = await db.get(key);
    if (value) {
      return JSON.parse(value);
    } else {
      return null;
    }
  }
  async set(key, value) {
    await db.put(key, JSON.stringify(value));
    return this;
  }
  async delete(key) {
    await db.del(key);
    return this;
  }
}
