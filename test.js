const fs = require('fs');

let rawdata = fs.readFileSync('./json/test.json');
let student = JSON.parse(rawdata);
student.name = "shan";
student.age = 12;
console.log(student);