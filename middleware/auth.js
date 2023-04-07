const userModel = require("../models/user");
const bcrypt = require("bcrypt-nodejs");
const checkLogin = async (req, res, next) => {
    const username = req.body.username;
    const user = await userModel.findOne({ username: username });
    if (user) {
        const isMatch = await bcrypt.compare(req.body.pass,user.pass);
        if(isMatch){
            next();
        }else{
            res.render('login',{layout:"form",err:"Thông tin đăng nhập không chính xác",username:username,pass:req.body.pass});
        }
        next();
    } else {
        res.render('login',{layout:"form",err:"Thông tin đăng nhập không chính xác",username:username,pass:req.body.pass});
    }
}

const checkAccount = async (req, res, next) => {
    const username = req.body.username;
    const user = await userModel.findOne({ username: username });
    if (user) {
        res.render('signup', { layout: "form", err: 'Thông tin đăng ký đã được sử dụng',username:username,pass:req.body.pass})
    } else {
        next();
    }
}

module.exports = {checkAccount,checkLogin};