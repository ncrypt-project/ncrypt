
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

/**
 * @namespace nCrypt.exception.types.basic
 * */

var basic = {};

basic.bn = require('./types/bn.js');
basic.secret = require('./types/secret.js');
basic.point = require('./types/point.js');
basic.id = require('./types/id.js');

module.exports = basic;
