const level = require('level')

//Create our database, supply location and options.
//This will create or open the underlying store.
const db = level('my-db')

if (!db.supports.permanence) {
  throw new Error('Persistent storage is required')
}

/*db.get('name', function (err, value) {
  if (err) {
    return console.log('Ooops!', err) // likely the key was not found
  }

  console.log('name=' + value);
})*/

module.exports = {
  async get(key) {
    const value = await db.get(key);
    if (value) {
      return JSON.parse(value);
    } else {
      return null;
    }
   list(prefix, values) {
    return new Promise(function(resolve, reject) {
      const obj = values ? {} : [];
      db.createReadStream();
      .on('data', function (data) {
        if(prefix && !data.key.startsWith(prefix)) {
          return;
        }
        if(values){
          obj[data.key] = JSON.parse(data.value);
        }else{
          obj.push(data.key);
        }
      });
      .on('error', function (err) {
        console.log('Oh my!', err);
        reject(err);
      });
      .on('close', function () {
        //console.log('Stream closed')
      });
      .on('end', function () {
        resolve(obj);
      });
    });
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
