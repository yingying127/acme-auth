const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const Sequelize = require('sequelize');
const { STRING } = Sequelize;
const config = {
  logging: false
};

if(process.env.LOGGING){
  delete config.logging;
}
const conn = new Sequelize(process.env.DATABASE_URL || 'postgres://localhost/acme_db', config);

const User = conn.define('user', {
  username: STRING,
  password: STRING
});

//added the hook below:
User.addHook('beforeSave', async(user) => {
  if (user.changed('password')) {
    // console.log(user.password)
    const hashed = await bcrypt.hash(user.password, 3)
    user.password = hashed
    console.log(hashed)
  }
})

User.byToken = async(token)=> {
  try {
    const payload = await jwt.verify(token, process.env.JWT)
    // console.log(payload) gets the id and iat (token)
    const user = await User.findByPk(payload.id, {
    //we dont send back the user.id, we send back the token that cannot be modified. 
      attributes: {
        exclude: ['password']
      }
    });
    if(user){
      return user;
    }
    const error = Error('bad credentials');
    error.status = 401;
    throw error;
  }
  catch(ex){
    const error = Error('bad credentials');
    error.status = 401;
    throw error;
  }
};

User.authenticate = async({ username, password })=> {
  const user = await User.findOne({
    where: {
      username
    }
  });
  if(user && await bcrypt.compare(password, user.password)){
    // if the hash pw is derived from the plain pw you gave it, it will return true
    return jwt.sign({ id: user.id }, process.env.JWT); 
  }
  const error = Error('bad credentials!!');
  error.status = 401;
  throw error;
};

const syncAndSeed = async()=> {
  await conn.sync({ force: true });
  const credentials = [
    { username: 'lucy', password: 'lucy_pw'},
    //inside FETCH/XHR in chrome console, you can see the token which is the id. 
    { username: 'moe', password: 'moe_pw'},
    { username: 'larry', password: 'larry_pw'}
  ];
  const [lucy, moe, larry] = await Promise.all(
    credentials.map( credential => User.create(credential))
  );
  return {
    users: {
      lucy,
      moe,
      larry
    }
  };
};

module.exports = {
  syncAndSeed,
  models: {
    User
  }
};
