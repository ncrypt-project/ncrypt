
/* nCrypt - Javascript cryptography made simple
 * Copyright (C) 2021 ncrypt-project
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * */

module.exports = (function(ncrypt, deptypes){

var tbasic = deptypes.basic;

/**
 * @namespace nCrypt.asym.types.key
 * */
var  key = {};
var _key = {};

key.keypair = require('./types/keypair.js');
key.keypair = key.keypair(ncrypt, { "basic": tbasic });

return key; });
