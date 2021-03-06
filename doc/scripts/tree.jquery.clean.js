(function() {
    var e, t, n, r, o, i, s, d, u, l, a, h, p, c, _, f, g, m, v, y, N, S, w, C, F = [].slice,
        D = {}.hasOwnProperty,
        E = function(e, t) {
            function n() {
                this.constructor = e
            }
            for (var r in t) D.call(t, r) && (e[r] = t[r]);
            return n.prototype = t.prototype, e.prototype = new n, e.__super__ = t.prototype, e
        };
    e = this.jQuery, m = function() {
        function t(t, n) {
            this.$el = e(t), this.options = e.extend({}, this.defaults, n)
        }
        return t.prototype.defaults = {}, t.prototype.destroy = function() {
            return this._deinit()
        }, t.prototype._init = function() {
            return null
        }, t.prototype._deinit = function() {
            return null
        }, t.register = function(n, r) {
            var o, i, s, d, u;
            return d = function() {
                return "simple_widget_" + r
            }, u = function(n, r) {
                var o;
                return o = e.data(n, r), o && o instanceof t ? o : null
            }, i = function(t, r) {
                var o, i, s, l, a, h;
                for (o = d(), a = 0, h = t.length; h > a; a++) i = t[a], s = u(i, o), s || (l = new n(i, r), e.data(i, o) || e.data(i, o, l), l._init());
                return t
            }, s = function(t) {
                var n, r, o, i, s, l;
                for (n = d(), l = [], i = 0, s = t.length; s > i; i++) r = t[i], o = u(r, n), o && o.destroy(), l.push(e.removeData(r, n));
                return l
            }, o = function(n, r, o) {
                var i, s, u, l, a, h;
                for (s = null, a = 0, h = n.length; h > a; a++) i = n[a], u = e.data(i, d()), u && u instanceof t && (l = u[r], l && "function" == typeof l && (s = l.apply(u, o)));
                return s
            }, e.fn[r] = function() {
                var e, t, n, r, d;
                return n = arguments[0], t = 2 <= arguments.length ? F.call(arguments, 1) : [], e = this, void 0 === n || "object" == typeof n ? (d = n, i(e, d)) : "string" == typeof n && "_" !== n[0] ? (r = n, "destroy" === r ? s(e) : o(e, r, t)) : void 0
            }
        }, t
    }(), this.SimpleWidget = m, a = function(t) {
        function n() {
            return n.__super__.constructor.apply(this, arguments)
        }
        return E(n, t), n.is_mouse_handled = !1, n.prototype._init = function() {
            return this.$el.bind("mousedown.mousewidget", e.proxy(this._mouseDown, this)), this.$el.bind("touchstart.mousewidget", e.proxy(this._touchStart, this)), this.is_mouse_started = !1, this.mouse_delay = 0, this._mouse_delay_timer = null, this._is_mouse_delay_met = !0, this.mouse_down_info = null
        }, n.prototype._deinit = function() {
            var t;
            return this.$el.unbind("mousedown.mousewidget"), this.$el.unbind("touchstart.mousewidget"), t = e(document), t.unbind("mousemove.mousewidget"), t.unbind("mouseup.mousewidget")
        }, n.prototype._mouseDown = function(e) {
            var t;
            if (1 === e.which) return t = this._handleMouseDown(e, this._getPositionInfo(e)), t && e.preventDefault(), t
        }, n.prototype._handleMouseDown = function(e, t) {
            return !n.is_mouse_handled && (this.is_mouse_started && this._handleMouseUp(t), this.mouse_down_info = t, this._mouseCapture(t)) ? (this._handleStartMouse(), this.is_mouse_handled = !0, !0) : void 0
        }, n.prototype._handleStartMouse = function() {
            var t;
            return t = e(document), t.bind("mousemove.mousewidget", e.proxy(this._mouseMove, this)), t.bind("touchmove.mousewidget", e.proxy(this._touchMove, this)), t.bind("mouseup.mousewidget", e.proxy(this._mouseUp, this)), t.bind("touchend.mousewidget", e.proxy(this._touchEnd, this)), this.mouse_delay ? this._startMouseDelayTimer() : void 0
        }, n.prototype._startMouseDelayTimer = function() {
            return this._mouse_delay_timer && clearTimeout(this._mouse_delay_timer), this._mouse_delay_timer = setTimeout(function(e) {
                return function() {
                    return e._is_mouse_delay_met = !0
                }
            }(this), this.mouse_delay), this._is_mouse_delay_met = !1
        }, n.prototype._mouseMove = function(e) {
            return this._handleMouseMove(e, this._getPositionInfo(e))
        }, n.prototype._handleMouseMove = function(e, t) {
            return this.is_mouse_started ? (this._mouseDrag(t), e.preventDefault()) : this.mouse_delay && !this._is_mouse_delay_met ? !0 : (this.is_mouse_started = this._mouseStart(this.mouse_down_info) !== !1, this.is_mouse_started ? this._mouseDrag(t) : this._handleMouseUp(t), !this.is_mouse_started)
        }, n.prototype._getPositionInfo = function(e) {
            return {
                page_x: e.pageX,
                page_y: e.pageY,
                target: e.target,
                original_event: e
            }
        }, n.prototype._mouseUp = function(e) {
            return this._handleMouseUp(this._getPositionInfo(e))
        }, n.prototype._handleMouseUp = function(t) {
            var n;
            n = e(document), n.unbind("mousemove.mousewidget"), n.unbind("touchmove.mousewidget"), n.unbind("mouseup.mousewidget"), n.unbind("touchend.mousewidget"), this.is_mouse_started && (this.is_mouse_started = !1, this._mouseStop(t))
        }, n.prototype._mouseCapture = function() {
            return !0
        }, n.prototype._mouseStart = function() {
            return null
        }, n.prototype._mouseDrag = function() {
            return null
        }, n.prototype._mouseStop = function() {
            return null
        }, n.prototype.setMouseDelay = function(e) {
            return this.mouse_delay = e
        }, n.prototype._touchStart = function(e) {
            var t;
            if (!(e.originalEvent.touches.length > 1)) return t = e.originalEvent.changedTouches[0], this._handleMouseDown(e, this._getPositionInfo(t))
        }, n.prototype._touchMove = function(e) {
            var t;
            if (!(e.originalEvent.touches.length > 1)) return t = e.originalEvent.changedTouches[0], this._handleMouseMove(e, this._getPositionInfo(t))
        }, n.prototype._touchEnd = function(e) {
            var t;
            if (!(e.originalEvent.touches.length > 1)) return t = e.originalEvent.changedTouches[0], this._handleMouseUp(this._getPositionInfo(t))
        }, n
    }(m), this.Tree = {}, e = this.jQuery, c = {
        getName: function(e) {
            return c.strings[e - 1]
        },
        nameToIndex: function(e) {
            var t, n, r;
            for (t = n = 1, r = c.strings.length; r >= 1 ? r >= n : n >= r; t = r >= 1 ? ++n : --n)
                if (c.strings[t - 1] === e) return t;
            return 0
        }
    }, c.BEFORE = 1, c.AFTER = 2, c.INSIDE = 3, c.NONE = 4, c.strings = ["before", "after", "inside", "none"], this.Tree.Position = c, h = function() {
        function t(e, n, r) {
            null == n && (n = !1), null == r && (r = t), this.setData(e), this.children = [], this.parent = null, n && (this.id_mapping = {}, this.tree = this, this.node_class = r)
        }
        return t.prototype.setData = function(e) {
            var t, n, r;
            if ("object" != typeof e) return this.name = e;
            r = [];
            for (t in e) n = e[t], "label" === t ? r.push(this.name = n) : r.push(this[t] = n);
            return r
        }, t.prototype.initFromData = function(e) {
            var t, n;
            return n = function(e) {
                return function(n) {
                    return e.setData(n), n.children ? t(n.children) : void 0
                }
            }(this), t = function(e) {
                return function(t) {
                    var n, r, o, i;
                    for (o = 0, i = t.length; i > o; o++) n = t[o], r = new e.tree.node_class(""), r.initFromData(n), e.addChild(r);
                    return null
                }
            }(this), n(e), null
        }, t.prototype.loadFromData = function(e) {
            var t, n, r, o;
            for (this.removeChildren(), r = 0, o = e.length; o > r; r++) n = e[r], t = new this.tree.node_class(n), this.addChild(t), "object" == typeof n && n.children && t.loadFromData(n.children);
            return null
        }, t.prototype.addChild = function(e) {
            return this.children.push(e), e._setParent(this)
        }, t.prototype.addChildAtPosition = function(e, t) {
            return this.children.splice(t, 0, e), e._setParent(this)
        }, t.prototype._setParent = function(e) {
            return this.parent = e, this.tree = e.tree, this.tree.addNodeToIndex(this)
        }, t.prototype.removeChild = function(e) {
            return e.removeChildren(), this._removeChild(e)
        }, t.prototype._removeChild = function(e) {
            return this.children.splice(this.getChildIndex(e), 1), this.tree.removeNodeFromIndex(e)
        }, t.prototype.getChildIndex = function(t) {
            return e.inArray(t, this.children)
        }, t.prototype.hasChildren = function() {
            return 0 !== this.children.length
        }, t.prototype.isFolder = function() {
            return this.hasChildren() || this.load_on_demand
        }, t.prototype.iterate = function(e) {
            var t;
            return t = function(n) {
                return function(r, o) {
                    var i, s, d, u, l;
                    if (r.children) {
                        for (l = r.children, d = 0, u = l.length; u > d; d++) i = l[d], s = e(i, o), n.hasChildren() && s && t(i, o + 1);
                        return null
                    }
                }
            }(this), t(this, 0), null
        }, t.prototype.moveNode = function(e, t, n) {
            return e.isParentOf(t) ? void 0 : (e.parent._removeChild(e), n === c.AFTER ? t.parent.addChildAtPosition(e, t.parent.getChildIndex(t) + 1) : n === c.BEFORE ? t.parent.addChildAtPosition(e, t.parent.getChildIndex(t)) : n === c.INSIDE ? t.addChildAtPosition(e, 0) : void 0)
        }, t.prototype.getData = function() {
            var e;
            return e = function() {
                return function(t) {
                    var n, r, o, i, s, d, u;
                    for (n = [], d = 0, u = t.length; u > d; d++) {
                        o = t[d], i = {};
                        for (r in o) s = o[r], "parent" !== r && "children" !== r && "element" !== r && "tree" !== r && Object.prototype.hasOwnProperty.call(o, r) && (i[r] = s);
                        o.hasChildren() && (i.children = e(o.children)), n.push(i)
                    }
                    return n
                }
            }(this), e(this.children)
        }, t.prototype.getNodeByName = function(e) {
            var t;
            return t = null, this.iterate(function(n) {
                return n.name === e ? (t = n, !1) : !0
            }), t
        }, t.prototype.addAfter = function(e) {
            var t, n;
            return this.parent ? (n = new this.tree.node_class(e), t = this.parent.getChildIndex(this), this.parent.addChildAtPosition(n, t + 1), n) : null
        }, t.prototype.addBefore = function(e) {
            var t, n;
            return this.parent ? (n = new this.tree.node_class(e), t = this.parent.getChildIndex(this), this.parent.addChildAtPosition(n, t), n) : null
        }, t.prototype.addParent = function(e) {
            var t, n, r, o, i, s;
            if (this.parent) {
                for (n = new this.tree.node_class(e), n._setParent(this.tree), r = this.parent, s = r.children, o = 0, i = s.length; i > o; o++) t = s[o], n.addChild(t);
                return r.children = [], r.addChild(n), n
            }
            return null
        }, t.prototype.remove = function() {
            return this.parent ? (this.parent.removeChild(this), this.parent = null) : void 0
        }, t.prototype.append = function(e) {
            var t;
            return t = new this.tree.node_class(e), this.addChild(t), t
        }, t.prototype.prepend = function(e) {
            var t;
            return t = new this.tree.node_class(e), this.addChildAtPosition(t, 0), t
        }, t.prototype.isParentOf = function(e) {
            var t;
            for (t = e.parent; t;) {
                if (t === this) return !0;
                t = t.parent
            }
            return !1
        }, t.prototype.getLevel = function() {
            var e, t;
            for (e = 0, t = this; t.parent;) e += 1, t = t.parent;
            return e
        }, t.prototype.getNodeById = function(e) {
            return this.id_mapping[e]
        }, t.prototype.addNodeToIndex = function(e) {
            return null != e.id ? this.id_mapping[e.id] = e : void 0
        }, t.prototype.removeNodeFromIndex = function(e) {
            return null != e.id ? delete this.id_mapping[e.id] : void 0
        }, t.prototype.removeChildren = function() {
            return this.iterate(function(e) {
                return function(t) {
                    return e.tree.removeNodeFromIndex(t), !0
                }
            }(this)), this.children = []
        }, t.prototype.getPreviousSibling = function() {
            var e;
            return this.parent ? (e = this.parent.getChildIndex(this) - 1, e >= 0 ? this.parent.children[e] : null) : null
        }, t.prototype.getNextSibling = function() {
            var e;
            return this.parent ? (e = this.parent.getChildIndex(this) + 1, e < this.parent.children.length ? this.parent.children[e] : null) : null
        }, t.prototype.getNodesByProperty = function(e, t) {
            return this.filter(function(n) {
                return n[e] === t
            })
        }, t.prototype.filter = function(e) {
            var t;
            return t = [], this.iterate(function(n) {
                return e(n) && t.push(n), !0
            }), t
        }, t
    }(), this.Tree.Node = h, o = function() {
        function t(e) {
            this.tree_widget = e, this.opened_icon_element = this.createButtonElement(e.options.openedIcon), this.closed_icon_element = this.createButtonElement(e.options.closedIcon)
        }
        return t.prototype.render = function(e) {
            return e && e.parent ? this.renderFromNode(e) : this.renderFromRoot()
        }, t.prototype.renderNode = function(t) {
            var n, r, o;
            return e(t.element).remove(), r = new p(t.parent, this.tree_widget), n = this.createLi(t), this.attachNodeData(t, n), o = t.getPreviousSibling(), o ? e(o.element).after(n) : r.getUl().prepend(n), t.children ? this.renderFromNode(t) : void 0
        }, t.prototype.renderFromRoot = function() {
            var e;
            return e = this.tree_widget.element, e.empty(), this.createDomElements(e[0], this.tree_widget.tree.children, !0, !0)
        }, t.prototype.renderFromNode = function(e) {
            var t;
            return t = this.tree_widget._getNodeElementForNode(e), t.getUl().remove(), this.createDomElements(t.$element[0], e.children, !1, !1)
        }, t.prototype.createDomElements = function(e, t, n) {
            var r, o, i, s, d;
            for (i = this.createUl(n), e.appendChild(i), s = 0, d = t.length; d > s; s++) r = t[s], o = this.createLi(r), i.appendChild(o), this.attachNodeData(r, o), r.hasChildren() && this.createDomElements(o, r.children, !1, r.is_open);
            return null
        }, t.prototype.attachNodeData = function(t, n) {
            return t.element = n, e(n).data("node", t)
        }, t.prototype.createUl = function(e) {
            var t, n;
            return t = e ? "jqtree-tree" : "", n = document.createElement("ul"), n.className = "jqtree_common " + t, n
        }, t.prototype.createLi = function(t) {
            var n;
            return n = t.isFolder() ? this.createFolderLi(t) : this.createNodeLi(t), this.tree_widget.options.onCreateLi && this.tree_widget.options.onCreateLi(t, e(n)), n
        }, t.prototype.createFolderLi = function(e) {
            var t, n, r, o, i, s, d, u;
            return t = this.getButtonClasses(e), i = this.getFolderClasses(e), o = this.escapeIfNecessary(e.name), s = e.is_open ? this.opened_icon_element : this.closed_icon_element, d = document.createElement("li"), d.className = "jqtree_common " + i, r = document.createElement("div"), r.className = "jqtree-element jqtree_common", d.appendChild(r), n = document.createElement("a"), n.className = "jqtree_common " + t, n.appendChild(s.cloneNode()), r.appendChild(n), u = document.createElement("span"), u.className = "jqtree_common jqtree-title jqtree-title-folder", r.appendChild(u), u.innerHTML = o, d
        }, t.prototype.createNodeLi = function(e) {
            var t, n, r, o, i, s;
            return i = ["jqtree_common"], this.tree_widget.select_node_handler && this.tree_widget.select_node_handler.isNodeSelected(e) && i.push("jqtree-selected"), t = i.join(" "), r = this.escapeIfNecessary(e.name), o = document.createElement("li"), o.className = t, n = document.createElement("div"), n.className = "jqtree-element jqtree_common", o.appendChild(n), s = document.createElement("span"), s.className = "jqtree-title jqtree_common", s.innerHTML = r, n.appendChild(s), o
        }, t.prototype.getButtonClasses = function(e) {
            var t;
            return t = ["jqtree-toggler"], e.is_open || t.push("jqtree-closed"), t.join(" ")
        }, t.prototype.getFolderClasses = function(e) {
            var t;
            return t = ["jqtree-folder"], e.is_open || t.push("jqtree-closed"), this.tree_widget.select_node_handler && this.tree_widget.select_node_handler.isNodeSelected(e) && t.push("jqtree-selected"), t.join(" ")
        }, t.prototype.escapeIfNecessary = function(e) {
            return this.tree_widget.options.autoEscape ? N(e) : e
        }, t.prototype.createButtonElement = function(t) {
            var n;
            return "string" == typeof t ? (n = document.createElement("div"), n.innerHTML = t, document.createTextNode(n.innerHTML)) : e(t)[0]
        }, t
    }(), u = function(t) {
        function r() {
            return r.__super__.constructor.apply(this, arguments)
        }
        return E(r, t), r.prototype.defaults = {
            autoOpen: !1,
            saveState: !1,
            dragAndDrop: !1,
            selectable: !0,
            useContextMenu: !0,
            onCanSelectNode: null,
            onSetStateFromStorage: null,
            onGetStateFromStorage: null,
            onCreateLi: null,
            onIsMoveHandle: null,
            onCanMove: null,
            onCanMoveTo: null,
            onLoadFailed: null,
            autoEscape: !0,
            dataUrl: null,
            closedIcon: "&#x25ba;",
            openedIcon: "&#x25bc;",
            slide: !0,
            nodeClass: h,
            dataFilter: null,
            keyboardSupport: !0,
            openFolderDelay: 500
        }, r.prototype.toggle = function(e, t) {
            return null == t && (t = !0), e.is_open ? this.closeNode(e, t) : this.openNode(e, t)
        }, r.prototype.getTree = function() {
            return this.tree
        }, r.prototype.selectNode = function(e) {
            return this._selectNode(e, !1)
        }, r.prototype._selectNode = function(e, t) {
            var n, r, o, i;
            if (null == t && (t = !1), this.select_node_handler) {
                if (n = function(t) {
                        return function() {
                            return t.options.onCanSelectNode ? t.options.selectable && t.options.onCanSelectNode(e) : t.options.selectable
                        }
                    }(this), o = function(t) {
                        return function() {
                            var n;
                            return n = e.parent, n && n.parent && !n.is_open ? t.openNode(n, !1) : void 0
                        }
                    }(this), i = function(e) {
                        return function() {
                            return e.options.saveState ? e.save_state_handler.saveState() : void 0
                        }
                    }(this), !e) return this._deselectCurrentNode(), i(), void 0;
                if (n()) return this.select_node_handler.isNodeSelected(e) ? t && (this._deselectCurrentNode(), this._triggerEvent("tree.select", {
                    node: null,
                    previous_node: e
                })) : (r = this.getSelectedNode(), this._deselectCurrentNode(), this.addToSelection(e), this._triggerEvent("tree.select", {
                    node: e,
                    deselected_node: r
                }), o()), i()
            }
        }, r.prototype.getSelectedNode = function() {
            return this.select_node_handler.getSelectedNode()
        }, r.prototype.toJson = function() {
            return JSON.stringify(this.tree.getData())
        }, r.prototype.loadData = function(e, t) {
            return this._loadData(e, t)
        }, r.prototype.loadDataFromUrl = function(t, n, r) {
            return "string" !== e.type(t) && (r = n, n = t, t = null), this._loadDataFromUrl(t, n, r)
        }, r.prototype.reload = function() {
            return this.loadDataFromUrl()
        }, r.prototype._loadDataFromUrl = function(t, n, r) {
            var o, s, d, u, l, a;
            if (o = null, s = function(e) {
                    return function() {
                        var t;
                        return n ? (t = new i(n, e), o = t.getLi()) : o = e.element, o.addClass("jqtree-loading")
                    }
                }(this), a = function() {
                    return function() {
                        return o ? o.removeClass("jqtree-loading") : void 0
                    }
                }(this), l = function() {
                    return function() {
                        return "string" === e.type(t) && (t = {
                            url: t
                        }), t.method ? void 0 : t.method = "get"
                    }
                }(this), d = function(t) {
                    return function(o) {
                        return a(), t._loadData(o, n), r && e.isFunction(r) ? r() : void 0
                    }
                }(this), u = function(n) {
                    return function() {
                        return l(), e.ajax({
                            url: t.url,
                            data: t.data,
                            type: t.method.toUpperCase(),
                            cache: !1,
                            dataType: "json",
                            success: function(t) {
                                var r;
                                return r = e.isArray(t) || "object" == typeof t ? t : e.parseJSON(t), n.options.dataFilter && (r = n.options.dataFilter(r)), d(r)
                            },
                            error: function(e) {
                                return a(), n.options.onLoadFailed ? n.options.onLoadFailed(e) : void 0
                            }
                        })
                    }
                }(this), t || (t = this._getDataUrlInfo(n)), s(), t === !1 || null === t) a();
            else {
                if (!e.isArray(t)) return u();
                d(t)
            }
        }, r.prototype._loadData = function(e, t) {
            var n, r, o, i;
            if (e) {
                if (this._triggerEvent("tree.load_data", {
                        tree_data: e
                    }), t) {
                    for (r = this.select_node_handler.getSelectedNodesUnder(t), o = 0, i = r.length; i > o; o++) n = r[o], this.select_node_handler.removeFromSelection(n);
                    t.loadFromData(e), t.load_on_demand = !1, this._refreshElements(t.parent)
                } else this._initTree(e);
                return this.isDragging() ? this.dnd_handler.refresh() : void 0
            }
        }, r.prototype.getNodeById = function(e) {
            return this.tree.getNodeById(e)
        }, r.prototype.getNodeByName = function(e) {
            return this.tree.getNodeByName(e)
        }, r.prototype.openNode = function(e, t) {
            return null == t && (t = !0), this._openNode(e, t)
        }, r.prototype._openNode = function(e, t, n) {
            var r, o;
            if (null == t && (t = !0), r = function(e) {
                    return function(t, n, r) {
                        var o;
                        return o = new i(t, e), o.open(r, n)
                    }
                }(this), e.isFolder()) {
                if (e.load_on_demand) return this._loadFolderOnDemand(e, t, n);
                for (o = e.parent; o && !o.is_open;) o.parent && r(o, !1, null), o = o.parent;
                return r(e, t, n), this._saveState()
            }
        }, r.prototype._loadFolderOnDemand = function(e, t, n) {
            return null == t && (t = !0), this._loadDataFromUrl(null, e, function(r) {
                return function() {
                    return r._openNode(e, t, n)
                }
            }(this))
        }, r.prototype.closeNode = function(e, t) {
            return null == t && (t = !0), e.isFolder() ? (new i(e, this).close(t), this._saveState()) : void 0
        }, r.prototype.isDragging = function() {
            return this.dnd_handler ? this.dnd_handler.is_dragging : !1
        }, r.prototype.refreshHitAreas = function() {
            return this.dnd_handler.refresh()
        }, r.prototype.addNodeAfter = function(e, t) {
            var n;
            return n = t.addAfter(e), this._refreshElements(t.parent), n
        }, r.prototype.addNodeBefore = function(e, t) {
            var n;
            return n = t.addBefore(e), this._refreshElements(t.parent), n
        }, r.prototype.addParentNode = function(e, t) {
            var n;
            return n = t.addParent(e), this._refreshElements(n.parent), n
        }, r.prototype.removeNode = function(e) {
            var t;
            return t = e.parent, t ? (this.select_node_handler.removeFromSelection(e, !0), e.remove(), this._refreshElements(t.parent)) : void 0
        }, r.prototype.appendNode = function(e, t) {
            var n, r;
            return t || (t = this.tree), n = t.isFolder(), r = t.append(e), n ? this._refreshElements(t) : this._refreshElements(t.parent), r
        }, r.prototype.prependNode = function(e, t) {
            var n;
            return t || (t = this.tree), n = t.prepend(e), this._refreshElements(t), n
        }, r.prototype.updateNode = function(e, t) {
            var n;
            return n = t.id && t.id !== e.id, n && this.tree.removeNodeFromIndex(e), e.setData(t), n && this.tree.addNodeToIndex(e), this.renderer.renderNode(e), this._selectCurrentNode()
        }, r.prototype.moveNode = function(e, t, n) {
            var r;
            return r = c.nameToIndex(n), this.tree.moveNode(e, t, r), this._refreshElements()
        }, r.prototype.getStateFromStorage = function() {
            return this.save_state_handler.getStateFromStorage()
        }, r.prototype.addToSelection = function(e) {
            return e ? (this.select_node_handler.addToSelection(e), this._getNodeElementForNode(e).select(), this._saveState()) : void 0
        }, r.prototype.getSelectedNodes = function() {
            return this.select_node_handler.getSelectedNodes()
        }, r.prototype.isNodeSelected = function(e) {
            return this.select_node_handler.isNodeSelected(e)
        }, r.prototype.removeFromSelection = function(e) {
            return this.select_node_handler.removeFromSelection(e), this._getNodeElementForNode(e).deselect(), this._saveState()
        }, r.prototype.scrollToNode = function(t) {
            var n, r;
            return n = e(t.element), r = n.offset().top - this.$el.offset().top, this.scroll_handler.scrollTo(r)
        }, r.prototype.getState = function() {
            return this.save_state_handler.getState()
        }, r.prototype.setState = function(e) {
            return this.save_state_handler.setState(e), this._refreshElements()
        }, r.prototype.setOption = function(e, t) {
            return this.options[e] = t
        }, r.prototype._init = function() {
            return r.__super__._init.call(this), this.element = this.$el, this.mouse_delay = 300, this.is_initialized = !1, this.renderer = new o(this), "undefined" != typeof _ && null !== _ ? this.save_state_handler = new _(this) : this.options.saveState = !1, "undefined" != typeof g && null !== g && (this.select_node_handler = new g(this)), "undefined" != typeof n && null !== n ? this.dnd_handler = new n(this) : this.options.dragAndDrop = !1, "undefined" != typeof f && null !== f && (this.scroll_handler = new f(this)), "undefined" != typeof l && null !== l && "undefined" != typeof g && null !== g && (this.key_handler = new l(this)), this._initData(), this.element.click(e.proxy(this._click, this)), this.element.dblclick(e.proxy(this._dblclick, this)), this.options.useContextMenu ? this.element.bind("contextmenu", e.proxy(this._contextmenu, this)) : void 0
        }, r.prototype._deinit = function() {
            return this.element.empty(), this.element.unbind(), this.key_handler.deinit(), this.tree = null, r.__super__._deinit.call(this)
        }, r.prototype._initData = function() {
            return this.options.data ? this._loadData(this.options.data) : this._loadDataFromUrl(this._getDataUrlInfo())
        }, r.prototype._getDataUrlInfo = function(t) {
            var n, r;
            return n = this.options.dataUrl || this.element.data("url"), r = function(e) {
                return function() {
                    var r, o, i;
                    return i = {
                        url: n
                    }, t && t.id ? (r = {
                        node: t.id
                    }, i.data = r) : (o = e._getNodeIdToBeSelected(), o && (r = {
                        selected_node: o
                    }, i.data = r)), i
                }
            }(this), e.isFunction(n) ? n(t) : "string" === e.type(n) ? r() : n
        }, r.prototype._getNodeIdToBeSelected = function() {
            return this.options.saveState ? this.save_state_handler.getNodeIdToBeSelected() : null
        }, r.prototype._initTree = function(e) {
            return this.tree = new this.options.nodeClass(null, !0, this.options.nodeClass), this.select_node_handler && this.select_node_handler.clear(), this.tree.loadFromData(e), this._openNodes(), this._refreshElements(), this.is_initialized ? void 0 : (this.is_initialized = !0, this._triggerEvent("tree.init"))
        }, r.prototype._openNodes = function() {
            var e;
            if (!(this.options.saveState && this.save_state_handler.restoreState() || this.options.autoOpen === !1)) return e = this.options.autoOpen === !0 ? -1 : parseInt(this.options.autoOpen), this.tree.iterate(function(t, n) {
                return t.hasChildren() && (t.is_open = !0), n !== e
            })
        }, r.prototype._refreshElements = function(e) {
            return null == e && (e = null), this.renderer.render(e), this._triggerEvent("tree.refresh")
        }, r.prototype._click = function(e) {
            var t, n, r;
            if (t = this._getClickTarget(e.target)) {
                if ("button" === t.type) return this.toggle(t.node, this.options.slide), e.preventDefault(), e.stopPropagation();
                if ("label" === t.type && (r = t.node, n = this._triggerEvent("tree.click", {
                        node: r,
                        click_event: e
                    }), !n.isDefaultPrevented())) return this._selectNode(r, !0)
            }
        }, r.prototype._dblclick = function(e) {
            var t;
            return t = this._getClickTarget(e.target), t && "label" === t.type ? this._triggerEvent("tree.dblclick", {
                node: t.node,
                click_event: e
            }) : void 0
        }, r.prototype._getClickTarget = function(t) {
            var n, r, o, i;
            if (o = e(t), n = o.closest(".jqtree-toggler"), n.length) {
                if (i = this._getNode(n)) return {
                    type: "button",
                    node: i
                }
            } else if (r = o.closest(".jqtree-element"), r.length && (i = this._getNode(r))) return {
                type: "label",
                node: i
            };
            return null
        }, r.prototype._getNode = function(e) {
            var t;
            return t = e.closest("li.jqtree_common"), 0 === t.length ? null : t.data("node")
        }, r.prototype._getNodeElementForNode = function(e) {
            return e.isFolder() ? new i(e, this) : new p(e, this)
        }, r.prototype._getNodeElement = function(e) {
            var t;
            return t = this._getNode(e), t ? this._getNodeElementForNode(t) : null
        }, r.prototype._contextmenu = function(t) {
            var n, r;
            return n = e(t.target).closest("ul.jqtree-tree .jqtree-element"), n.length && (r = this._getNode(n)) ? (t.preventDefault(), t.stopPropagation(), this._triggerEvent("tree.contextmenu", {
                node: r,
                click_event: t
            }), !1) : void 0
        }, r.prototype._saveState = function() {
            return this.options.saveState ? this.save_state_handler.saveState() : void 0
        }, r.prototype._mouseCapture = function(e) {
            return this.options.dragAndDrop ? this.dnd_handler.mouseCapture(e) : !1
        }, r.prototype._mouseStart = function(e) {
            return this.options.dragAndDrop ? this.dnd_handler.mouseStart(e) : !1
        }, r.prototype._mouseDrag = function(e) {
            var t;
            return this.options.dragAndDrop ? (t = this.dnd_handler.mouseDrag(e), this.scroll_handler && this.scroll_handler.checkScrolling(), t) : !1
        }, r.prototype._mouseStop = function(e) {
            return this.options.dragAndDrop ? this.dnd_handler.mouseStop(e) : !1
        }, r.prototype._triggerEvent = function(t, n) {
            var r;
            return r = e.Event(t), e.extend(r, n), this.element.trigger(r), r
        }, r.prototype.testGenerateHitAreas = function(e) {
            return this.dnd_handler.current_item = this._getNodeElementForNode(e), this.dnd_handler.generateHitAreas(), this.dnd_handler.hit_areas
        }, r.prototype._selectCurrentNode = function() {
            var e, t;
            return e = this.getSelectedNode(), e && (t = this._getNodeElementForNode(e)) ? t.select() : void 0
        }, r.prototype._deselectCurrentNode = function() {
            var e;
            return e = this.getSelectedNode(), e ? this.removeFromSelection(e) : void 0
        }, r
    }(a), m.register(u, "tree"), p = function() {
        function n(e, t) {
            this.init(e, t)
        }
        return n.prototype.init = function(t, n) {
            return this.node = t, this.tree_widget = n, t.element || (t.element = this.tree_widget.element), this.$element = e(t.element)
        }, n.prototype.getUl = function() {
            return this.$element.children("ul:first")
        }, n.prototype.getSpan = function() {
            return this.$element.children(".jqtree-element").find("span.jqtree-title")
        }, n.prototype.getLi = function() {
            return this.$element
        }, n.prototype.addDropHint = function(e) {
            return e === c.INSIDE ? new t(this.$element) : new s(this.node, this.$element, e)
        }, n.prototype.select = function() {
            return this.getLi().addClass("jqtree-selected")
        }, n.prototype.deselect = function() {
            return this.getLi().removeClass("jqtree-selected")
        }, n
    }(), i = function(e) {
        function n() {
            return n.__super__.constructor.apply(this, arguments)
        }
        return E(n, e), n.prototype.open = function(e, t) {
            var n, r;
            return null == t && (t = !0), this.node.is_open ? void 0 : (this.node.is_open = !0, n = this.getButton(), n.removeClass("jqtree-closed"), n.html(""), n.append(this.tree_widget.renderer.opened_icon_element.cloneNode()), r = function(t) {
                return function() {
                    return t.getLi().removeClass("jqtree-closed"), e && e(), t.tree_widget._triggerEvent("tree.open", {
                        node: t.node
                    })
                }
            }(this), t ? this.getUl().slideDown("fast", r) : (this.getUl().show(), r()))
        }, n.prototype.close = function(e) {
            var t, n;
            return null == e && (e = !0), this.node.is_open ? (this.node.is_open = !1, t = this.getButton(), t.addClass("jqtree-closed"), t.html(""), t.append(this.tree_widget.renderer.closed_icon_element.cloneNode()), n = function(e) {
                return function() {
                    return e.getLi().addClass("jqtree-closed"), e.tree_widget._triggerEvent("tree.close", {
                        node: e.node
                    })
                }
            }(this), e ? this.getUl().slideUp("fast", n) : (this.getUl().hide(), n())) : void 0
        }, n.prototype.getButton = function() {
            return this.$element.children(".jqtree-element").find("a.jqtree-toggler")
        }, n.prototype.addDropHint = function(e) {
            return this.node.is_open || e !== c.INSIDE ? new s(this.node, this.$element, e) : new t(this.$element)
        }, n
    }(p), N = function(e) {
        return ("" + e).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#x27;").replace(/\//g, "&#x2F;")
    }, C = function(e, t) {
        var n, r, o, i;
        for (n = o = 0, i = e.length; i > o; n = ++o)
            if (r = e[n], r === t) return n;
        return -1
    }, S = function(e, t) {
        return e.indexOf ? e.indexOf(t) : C(e, t)
    }, this.Tree.indexOf = S, this.Tree._indexOf = C, w = function(e) {
        return "number" == typeof e && e % 1 === 0
    }, y = function() {
        var e, t, n, r, o;
        return e = /[\\\"\x00-\x1f\x7f-\x9f\u00ad\u0600-\u0604\u070f\u17b4\u17b5\u200c-\u200f\u2028-\u202f\u2060-\u206f\ufeff\ufff0-\uffff]/g, t = {
            "\b": "\\b",
            "	": "\\t",
            "\n": "\\n",
            "\f": "\\f",
            "\r": "\\r",
            '"': '\\"',
            "\\": "\\\\"
        }, n = function(n) {
            return e.lastIndex = 0, e.test(n) ? '"' + n.replace(e, function(e) {
                var n;
                return n = t[e], "string" == typeof n ? n : "\\u" + ("0000" + e.charCodeAt(0).toString(16)).slice(-4)
            }) + '"' : '"' + n + '"'
        }, r = function(e, t) {
            var o, i, s, d, u, l, a;
            switch (u = t[e], typeof u) {
                case "string":
                    return n(u);
                case "number":
                    return isFinite(u) ? String(u) : "null";
                case "boolean":
                case "null":
                    return String(u);
                case "object":
                    if (!u) return "null";
                    if (s = [], "[object Array]" === Object.prototype.toString.apply(u)) {
                        for (o = l = 0, a = u.length; a > l; o = ++l) d = u[o], s[o] = r(o, u) || "null";
                        return 0 === s.length ? "[]" : "[" + s.join(",") + "]"
                    }
                    for (i in u) Object.prototype.hasOwnProperty.call(u, i) && (d = r(i, u), d && s.push(n(i) + ":" + d));
                    return 0 === s.length ? "{}" : "{" + s.join(",") + "}"
            }
        }, o = function(e) {
            return r("", {
                "": e
            })
        }
    }, this.Tree.get_json_stringify_function = y, (null == this.JSON || null == this.JSON.stringify || "function" != typeof this.JSON.stringify) && (null == this.JSON && (this.JSON = {}), this.JSON.stringify = y()), _ = function() {
        function t(e) {
            this.tree_widget = e
        }
        return t.prototype.saveState = function() {
            var t;
            return t = JSON.stringify(this.getState()), this.tree_widget.options.onSetStateFromStorage ? this.tree_widget.options.onSetStateFromStorage(t) : this.supportsLocalStorage() ? localStorage.setItem(this.getCookieName(), t) : e.cookie ? (e.cookie.raw = !0, e.cookie(this.getCookieName(), t, {
                path: "/"
            })) : void 0
        }, t.prototype.restoreState = function() {
            var t;
            return t = this.getStateFromStorage(), t ? (this.setState(e.parseJSON(t)), !0) : !1
        }, t.prototype.getStateFromStorage = function() {
            return this.tree_widget.options.onGetStateFromStorage ? this.tree_widget.options.onGetStateFromStorage() : this.supportsLocalStorage() ? localStorage.getItem(this.getCookieName()) : e.cookie ? (e.cookie.raw = !0, e.cookie(this.getCookieName())) : null
        }, t.prototype.getState = function() {
            var e, t;
            return e = function(e) {
                return function() {
                    var t;
                    return t = [], e.tree_widget.tree.iterate(function(e) {
                        return e.is_open && e.id && e.hasChildren() && t.push(e.id), !0
                    }), t
                }
            }(this), t = function(e) {
                return function() {
                    var t;
                    return function() {
                        var e, n, r, o;
                        for (r = this.tree_widget.getSelectedNodes(), o = [], e = 0, n = r.length; n > e; e++) t = r[e], o.push(t.id);
                        return o
                    }.call(e)
                }
            }(this), {
                open_nodes: e(),
                selected_node: t()
            }
        }, t.prototype.setState = function(e) {
            var t, n, r, o, i, s, d;
            if (e && (n = e.open_nodes, o = e.selected_node, w(o) && (o = [o]), this.tree_widget.tree.iterate(function() {
                    return function(e) {
                        return e.is_open = e.id && e.hasChildren() && S(n, e.id) >= 0, !0
                    }
                }(this)), o && this.tree_widget.select_node_handler)) {
                for (this.tree_widget.select_node_handler.clear(), d = [], i = 0, s = o.length; s > i; i++) t = o[i], r = this.tree_widget.getNodeById(t), r ? d.push(this.tree_widget.select_node_handler.addToSelection(r)) : d.push(void 0);
                return d
            }
        }, t.prototype.getCookieName = function() {
            return "string" == typeof this.tree_widget.options.saveState ? this.tree_widget.options.saveState : "tree"
        }, t.prototype.supportsLocalStorage = function() {
            var e;
            return e = function() {
                var e, t;
                if ("undefined" == typeof localStorage || null === localStorage) return !1;
                try {
                    t = "_storage_test", sessionStorage.setItem(t, !0), sessionStorage.removeItem(t)
                } catch (n) {
                    return e = n, !1
                }
                return !0
            }, null == this._supportsLocalStorage && (this._supportsLocalStorage = e()), this._supportsLocalStorage
        }, t.prototype.getNodeIdToBeSelected = function() {
            var t, n;
            return n = this.getStateFromStorage(), n ? (t = e.parseJSON(n), t.selected_node) : null
        }, t
    }(), g = function() {
        function e(e) {
            this.tree_widget = e, this.clear()
        }
        return e.prototype.getSelectedNode = function() {
            var e;
            return e = this.getSelectedNodes(), e.length ? e[0] : !1
        }, e.prototype.getSelectedNodes = function() {
            var e, t, n;
            if (this.selected_single_node) return [this.selected_single_node];
            n = [];
            for (e in this.selected_nodes) t = this.tree_widget.getNodeById(e), t && n.push(t);
            return n
        }, e.prototype.getSelectedNodesUnder = function(e) {
            var t, n, r;
            if (this.selected_single_node) return e.isParentOf(this.selected_single_node) ? [this.selected_single_node] : [];
            r = [];
            for (t in this.selected_nodes) n = this.tree_widget.getNodeById(t), n && e.isParentOf(n) && r.push(n);
            return r
        }, e.prototype.isNodeSelected = function(e) {
            return e.id ? this.selected_nodes[e.id] : this.selected_single_node ? this.selected_single_node.element === e.element : !1
        }, e.prototype.clear = function() {
            return this.selected_nodes = {}, this.selected_single_node = null
        }, e.prototype.removeFromSelection = function(e, t) {
            if (null == t && (t = !1), e.id) {
                if (delete this.selected_nodes[e.id], t) return e.iterate(function(t) {
                    return function() {
                        return delete t.selected_nodes[e.id], !0
                    }
                }(this))
            } else if (this.selected_single_node && e.element === this.selected_single_node.element) return this.selected_single_node = null
        }, e.prototype.addToSelection = function(e) {
            return e.id ? this.selected_nodes[e.id] = !0 : this.selected_single_node = e
        }, e
    }(), n = function() {
        function t(e) {
            this.tree_widget = e, this.hovered_area = null, this.$ghost = null, this.hit_areas = [], this.is_dragging = !1, this.current_item = null
        }
        return t.prototype.mouseCapture = function(t) {
            var n, r;
            return n = e(t.target), this.mustCaptureElement(n) ? this.tree_widget.options.onIsMoveHandle && !this.tree_widget.options.onIsMoveHandle(n) ? null : (r = this.tree_widget._getNodeElement(n), r && this.tree_widget.options.onCanMove && (this.tree_widget.options.onCanMove(r.node) || (r = null)), this.current_item = r, null !== this.current_item) : null
        }, t.prototype.mouseStart = function(t) {
            var n;
            return this.refresh(), n = e(t.target).offset(), this.drag_element = new r(this.current_item.node, t.page_x - n.left, t.page_y - n.top, this.tree_widget.element), this.is_dragging = !0, this.current_item.$element.addClass("jqtree-moving"), !0
        }, t.prototype.mouseDrag = function(e) {
            var t, n;
            return this.drag_element.move(e.page_x, e.page_y), t = this.findHoveredArea(e.page_x, e.page_y), n = this.canMoveToArea(t), n && t ? this.hovered_area !== t && (this.hovered_area = t, this.mustOpenFolderTimer(t) && this.startOpenFolderTimer(t.node), this.updateDropHint()) : (this.removeHover(), this.removeDropHint(), this.stopOpenFolderTimer()), !0
        }, t.prototype.mustCaptureElement = function(e) {
            return !e.is("input,select")
        }, t.prototype.canMoveToArea = function(e) {
            var t;
            return e ? this.tree_widget.options.onCanMoveTo ? (t = c.getName(e.position), this.tree_widget.options.onCanMoveTo(this.current_item.node, e.node, t)) : !0 : !1
        }, t.prototype.mouseStop = function(e) {
            return this.moveItem(e), this.clear(), this.removeHover(), this.removeDropHint(), this.removeHitAreas(), this.current_item && (this.current_item.$element.removeClass("jqtree-moving"), this.current_item = null), this.is_dragging = !1, !1
        }, t.prototype.refresh = function() {
            return this.removeHitAreas(), this.generateHitAreas(), this.current_item && (this.current_item = this.tree_widget._getNodeElementForNode(this.current_item.node), this.is_dragging) ? this.current_item.$element.addClass("jqtree-moving") : void 0
        }, t.prototype.removeHitAreas = function() {
            return this.hit_areas = []
        }, t.prototype.clear = function() {
            return this.drag_element.remove(), this.drag_element = null
        }, t.prototype.removeDropHint = function() {
            return this.previous_ghost ? this.previous_ghost.remove() : void 0
        }, t.prototype.removeHover = function() {
            return this.hovered_area = null
        }, t.prototype.generateHitAreas = function() {
            var e;
            return e = new d(this.tree_widget.tree, this.current_item.node, this.getTreeDimensions().bottom), this.hit_areas = e.generate()
        }, t.prototype.findHoveredArea = function(e, t) {
            var n, r, o, i, s;
            if (r = this.getTreeDimensions(), e < r.left || t < r.top || e > r.right || t > r.bottom) return null;
            for (i = 0, o = this.hit_areas.length; o > i;)
                if (s = i + o >> 1, n = this.hit_areas[s], t < n.top) o = s;
                else {
                    if (!(t > n.bottom)) return n;
                    i = s + 1
                }
            return null
        }, t.prototype.mustOpenFolderTimer = function(e) {
            var t;
            return t = e.node, t.isFolder() && !t.is_open && e.position === c.INSIDE
        }, t.prototype.updateDropHint = function() {
            var e;
            if (this.hovered_area) return this.removeDropHint(), e = this.tree_widget._getNodeElementForNode(this.hovered_area.node), this.previous_ghost = e.addDropHint(this.hovered_area.position)
        }, t.prototype.startOpenFolderTimer = function(e) {
            var t;
            return t = function(t) {
                return function() {
                    return t.tree_widget._openNode(e, t.tree_widget.options.slide, function() {
                        return t.refresh(), t.updateDropHint()
                    })
                }
            }(this), this.stopOpenFolderTimer(), this.open_folder_timer = setTimeout(t, this.tree_widget.options.openFolderDelay)
        }, t.prototype.stopOpenFolderTimer = function() {
            return this.open_folder_timer ? (clearTimeout(this.open_folder_timer), this.open_folder_timer = null) : void 0
        }, t.prototype.moveItem = function(e) {
            var t, n, r, o, i, s;
            return this.hovered_area && this.hovered_area.position !== c.NONE && this.canMoveToArea(this.hovered_area) && (r = this.current_item.node, s = this.hovered_area.node, o = this.hovered_area.position, i = r.parent, o === c.INSIDE && (this.hovered_area.node.is_open = !0), t = function(e) {
                return function() {
                    return e.tree_widget.tree.moveNode(r, s, o), e.tree_widget.element.empty(), e.tree_widget._refreshElements()
                }
            }(this), n = this.tree_widget._triggerEvent("tree.move", {
                move_info: {
                    moved_node: r,
                    target_node: s,
                    position: c.getName(o),
                    previous_parent: i,
                    do_move: t,
                    original_event: e.original_event
                }
            }), !n.isDefaultPrevented()) ? t() : void 0
        }, t.prototype.getTreeDimensions = function() {
            var e;
            return e = this.tree_widget.element.offset(), {
                left: e.left,
                top: e.top,
                right: e.left + this.tree_widget.element.width(),
                bottom: e.top + this.tree_widget.element.height() + 16
            }
        }, t
    }(), v = function() {
        function t(e) {
            this.tree = e
        }
        return t.prototype.iterate = function() {
            var t, n;
            return t = !0, n = function(r) {
                return function(o, i) {
                    var s, d, u, l, a, h, p, c;
                    if (a = (o.is_open || !o.element) && o.hasChildren(), o.element) {
                        if (s = e(o.element), !s.is(":visible")) return;
                        t && (r.handleFirstNode(o, s), t = !1), o.hasChildren() ? o.is_open ? r.handleOpenFolder(o, s) || (a = !1) : r.handleClosedFolder(o, i, s) : r.handleNode(o, i, s)
                    }
                    if (a) {
                        for (u = o.children.length, c = o.children, l = h = 0, p = c.length; p > h; l = ++h) d = c[l], l === u - 1 ? n(o.children[l], null) : n(o.children[l], o.children[l + 1]);
                        if (o.is_open) return r.handleAfterOpenFolder(o, i, s)
                    }
                }
            }(this), n(this.tree, null)
        }, t.prototype.handleNode = function() {}, t.prototype.handleOpenFolder = function() {}, t.prototype.handleClosedFolder = function() {}, t.prototype.handleAfterOpenFolder = function() {}, t.prototype.handleFirstNode = function() {}, t
    }(), d = function(t) {
        function n(e, t, r) {
            n.__super__.constructor.call(this, e), this.current_node = t, this.tree_bottom = r
        }
        return E(n, t), n.prototype.generate = function() {
            return this.positions = [], this.last_top = 0, this.iterate(), this.generateHitAreas(this.positions)
        }, n.prototype.getTop = function(e) {
            return e.offset().top
        }, n.prototype.addPosition = function(e, t, n) {
            var r;
            return r = {
                top: n,
                node: e,
                position: t
            }, this.positions.push(r), this.last_top = n
        }, n.prototype.handleNode = function(e, t, n) {
            var r;
            return r = this.getTop(n), e === this.current_node ? this.addPosition(e, c.NONE, r) : this.addPosition(e, c.INSIDE, r), t === this.current_node || e === this.current_node ? this.addPosition(e, c.NONE, r) : this.addPosition(e, c.AFTER, r)
        }, n.prototype.handleOpenFolder = function(e, t) {
            return e === this.current_node ? !1 : (e.children[0] !== this.current_node && this.addPosition(e, c.INSIDE, this.getTop(t)), !0)
        }, n.prototype.handleClosedFolder = function(e, t, n) {
            var r;
            return r = this.getTop(n), e === this.current_node ? this.addPosition(e, c.NONE, r) : (this.addPosition(e, c.INSIDE, r), t !== this.current_node ? this.addPosition(e, c.AFTER, r) : void 0)
        }, n.prototype.handleFirstNode = function(t) {
            return t !== this.current_node ? this.addPosition(t, c.BEFORE, this.getTop(e(t.element))) : void 0
        }, n.prototype.handleAfterOpenFolder = function(e, t) {
            return e === this.current_node.node || t === this.current_node.node ? this.addPosition(e, c.NONE, this.last_top) : this.addPosition(e, c.AFTER, this.last_top)
        }, n.prototype.generateHitAreas = function(e) {
            var t, n, r, o, i, s;
            for (o = -1, t = [], n = [], i = 0, s = e.length; s > i; i++) r = e[i], r.top !== o && t.length && (t.length && this.generateHitAreasForGroup(n, t, o, r.top), o = r.top, t = []), t.push(r);
            return this.generateHitAreasForGroup(n, t, o, this.tree_bottom), n
        }, n.prototype.generateHitAreasForGroup = function(e, t, n, r) {
            var o, i, s, d, u;
            for (u = Math.min(t.length, 4), o = Math.round((r - n) / u), i = n, s = 0; u > s;) d = t[s], e.push({
                top: i,
                bottom: i + o,
                node: d.node,
                position: d.position
            }), i += o, s += 1;
            return null
        }, n
    }(v), r = function() {
        function t(t, n, r, o) {
            this.offset_x = n, this.offset_y = r, this.$element = e('<span class="jqtree-title jqtree-dragging">' + t.name + "</span>"), this.$element.css("position", "absolute"), o.append(this.$element)
        }
        return t.prototype.move = function(e, t) {
            return this.$element.offset({
                left: e - this.offset_x,
                top: t - this.offset_y
            })
        }, t.prototype.remove = function() {
            return this.$element.remove()
        }, t
    }(), s = function() {
        function t(t, n, r) {
            this.$element = n, this.node = t, this.$ghost = e('<li class="jqtree_common jqtree-ghost"><span class="jqtree_common jqtree-circle"></span><span class="jqtree_common jqtree-line"></span></li>'), r === c.AFTER ? this.moveAfter() : r === c.BEFORE ? this.moveBefore() : r === c.INSIDE && (t.isFolder() && t.is_open ? this.moveInsideOpenFolder() : this.moveInside())
        }
        return t.prototype.remove = function() {
            return this.$ghost.remove()
        }, t.prototype.moveAfter = function() {
            return this.$element.after(this.$ghost)
        }, t.prototype.moveBefore = function() {
            return this.$element.before(this.$ghost)
        }, t.prototype.moveInsideOpenFolder = function() {
            return e(this.node.children[0].element).before(this.$ghost)
        }, t.prototype.moveInside = function() {
            return this.$element.after(this.$ghost), this.$ghost.addClass("jqtree-inside")
        }, t
    }(), t = function() {
        function t(t) {
            var n, r;
            n = t.children(".jqtree-element"), r = t.width() - 4, this.$hint = e('<span class="jqtree-border"></span>'), n.append(this.$hint), this.$hint.css({
                width: r,
                height: n.height() - 4
            })
        }
        return t.prototype.remove = function() {
            return this.$hint.remove()
        }, t
    }(), f = function() {
        function t(e) {
            this.tree_widget = e, this.previous_top = -1, this._initScrollParent()
        }
        return t.prototype._initScrollParent = function() {
            var t, n, r;
            return n = function(t) {
                return function() {
                    var n, r, o, i, s, d;
                    if (n = ["overflow", "overflow-y"], o = function(t) {
                            var r, o, i, s;
                            for (o = 0, i = n.length; i > o; o++)
                                if (r = n[o], "auto" === (s = e.css(t, r)) || "scroll" === s) return !0;
                            return !1
                        }, o(t.tree_widget.$el[0])) return t.tree_widget.$el;
                    for (d = t.tree_widget.$el.parents(), i = 0, s = d.length; s > i; i++)
                        if (r = d[i], o(r)) return e(r);
                    return null
                }
            }(this), r = function(e) {
                return function() {
                    return e.scroll_parent_top = 0, e.$scroll_parent = null
                }
            }(this), "fixed" === this.tree_widget.$el.css("position") && r(), t = n(), t && t.length && "HTML" !== t[0].tagName ? (this.$scroll_parent = t, this.scroll_parent_top = this.$scroll_parent.offset().top) : r()
        }, t.prototype.checkScrolling = function() {
            var e;
            return e = this.tree_widget.dnd_handler.hovered_area, e && e.top !== this.previous_top ? (this.previous_top = e.top, this.$scroll_parent ? this._handleScrollingWithScrollParent(e) : this._handleScrollingWithDocument(e)) : void 0
        }, t.prototype._handleScrollingWithScrollParent = function(e) {
            var t;
            return t = this.scroll_parent_top + this.$scroll_parent[0].offsetHeight - e.bottom, 20 > t ? (this.$scroll_parent[0].scrollTop += 20, this.tree_widget.refreshHitAreas(), this.previous_top = -1) : e.top - this.scroll_parent_top < 20 ? (this.$scroll_parent[0].scrollTop -= 20, this.tree_widget.refreshHitAreas(), this.previous_top = -1) : void 0
        }, t.prototype._handleScrollingWithDocument = function(t) {
            var n;
            return n = t.top - e(document).scrollTop(), 20 > n ? e(document).scrollTop(e(document).scrollTop() - 20) : e(window).height() - (t.bottom - e(document).scrollTop()) < 20 ? e(document).scrollTop(e(document).scrollTop() + 20) : void 0
        }, t.prototype.scrollTo = function(t) {
            var n;
            return this.$scroll_parent ? this.$scroll_parent[0].scrollTop = t : (n = this.tree_widget.$el.offset().top, e(document).scrollTop(t + n))
        }, t.prototype.isScrolledIntoView = function(t) {
            var n, r, o, i, s;
            return n = e(t), this.$scroll_parent ? (s = 0, i = this.$scroll_parent.height(), o = n.offset().top - this.scroll_parent_top, r = o + n.height()) : (s = e(window).scrollTop(), i = s + e(window).height(), o = n.offset().top, r = o + n.height()), i >= r && o >= s
        }, t
    }(), l = function() {
        function t(t) {
            this.tree_widget = t, t.options.keyboardSupport && e(document).bind("keydown.jqtree", e.proxy(this.handleKeyDown, this))
        }
        var n, r, o, i;
        return r = 37, i = 38, o = 39, n = 40, t.prototype.deinit = function() {
            return e(document).unbind("keydown.jqtree")
        }, t.prototype.handleKeyDown = function(t) {
            var s, d, u, l, a, h, p;
            if (this.tree_widget.options.keyboardSupport) {
                if (e(document.activeElement).is("textarea,input,select")) return !0;
                if (s = this.tree_widget.getSelectedNode(), p = function(t) {
                        return function(n) {
                            return n ? (t.tree_widget.selectNode(n), t.tree_widget.scroll_handler && !t.tree_widget.scroll_handler.isScrolledIntoView(e(n.element).find(".jqtree-element")) && t.tree_widget.scrollToNode(n), !1) : !0
                        }
                    }(this), u = function(e) {
                        return function() {
                            return p(e.getNextNode(s))
                        }
                    }(this), h = function(e) {
                        return function() {
                            return p(e.getPreviousNode(s))
                        }
                    }(this), a = function(e) {
                        return function() {
                            return s.isFolder() && !s.is_open ? (e.tree_widget.openNode(s), !1) : !0
                        }
                    }(this), l = function(e) {
                        return function() {
                            return s.isFolder() && s.is_open ? (e.tree_widget.closeNode(s), !1) : !0
                        }
                    }(this), !s) return !0;
                switch (d = t.which) {
                    case n:
                        return u();
                    case i:
                        return h();
                    case o:
                        return a();
                    case r:
                        return l()
                }
            }
        }, t.prototype.getNextNode = function(e, t) {
            var n;
            return null == t && (t = !0), t && e.hasChildren() && e.is_open ? e.children[0] : e.parent ? (n = e.getNextSibling(), n ? n : this.getNextNode(e.parent, !1)) : null
        }, t.prototype.getPreviousNode = function(e) {
            var t;
            return e.parent ? (t = e.getPreviousSibling(), t ? t.hasChildren() && t.is_open ? this.getLastChild(t) : t : e.parent.parent ? e.parent : null) : null
        }, t.prototype.getLastChild = function(e) {
            var t;
            return e.hasChildren() ? (t = e.children[e.children.length - 1], t.hasChildren() && t.is_open ? this.getLastChild(t) : t) : null
        }, t
    }()
}).call(this);
