//(function () {
"use strict";
function login(provider) {
    location.replace('/Login/Index?provider=' + provider);
}
//}()); //TODO: don't work with IIFE for now