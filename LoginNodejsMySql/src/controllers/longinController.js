const bcrypt = require('bcrypt');

function login(req, res){ 
  if (req.session.loggedin) { 
    res.redirect('/'); 
  } else {
    res.render('login/index');
  }
    
}

function auth(req, res){
    const data = req.body;
    req.getConnection((err, conn) => {
        conn.query("SELECT * FROM usuarios WHERE email = ?", [data.email],(err, userdata) => {
          if(userdata.length > 0 ){
            userdata.forEach(element => { 
                bcrypt.compare(data.password, element.password, (err, isMatch) => {
                        if(!isMatch){
                            res.render('login/index', {error: 'Error: la contraseña es incorrecta!.'});
                        } else {
                            req.session.loggedin = true;
                            req.session.name = element.name;

                            res.redirect('/');
                        }
                    }
                );
                
            });
          } else {
            res.render('login/index', {error: 'Error: el usuario no existe!.'});
          }
        });
    });
}

function register(req, res){
    if (req.session.loggedin){
        res.redirect('/'); 
    }else{
        res.render('login/register');
    }
    
}

function storeUser(req, res){
    const data = req.body;
    
    req.getConnection((err, conn) => {
        conn.query("SELECT * FROM usuarios WHERE email = ?", [data.email],(err, userdata) => {
          if(userdata.length > 0 ){
            res.render('login/register', {error: 'Error: usuario registrado!.'});
          } else {

            bcrypt.hash(data.password, 12).then(hash => {
                data.password = hash;
                
                req.getConnection((err, conn) => {
                    conn.query('INSERT INTO usuarios SET ?', [data], (err, rows) => {
                        req.session.loggedin = true;
                        req.session.name = data.name;

                        res.redirect('/');
                    });
        
                });
        
            });

          }
        });
    });

    
}

function logout(req, res){
  if(req.session.loggedin){
    req.session.destroy();
  } 
  res.redirect('/'); 
}


module.exports = {
    login,
    register,
    storeUser,
    auth,
    logout,
}