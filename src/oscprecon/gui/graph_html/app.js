// Renders the profile graph with Cytoscape.js and talks to the Qt GraphBridge over QWebChannel.
// Node/edge colors follow CLAUDE.md §16. No network — cytoscape.min.js / cytoscape-svg.js are vendored,
// qwebchannel.js is served by Qt from qrc://. The minimap is a second locked Cytoscape overview (no
// jQuery-dependent navigator extension).
//
// Refresh model: after a scan, Qt re-pushes data by calling window.oscpRefresh() (see graph_view.py)
// rather than reloading the whole page — a full reload reinitialises the Chromium page + bridge each
// time and blanks the canvas on any hiccup. boot() retries until the QWebChannel transport is ready
// and shows a visible message instead of silently failing, so an empty canvas always explains itself.
(function () {
  "use strict";
  var cy = null;
  var mini = null;
  var bridge = null;
  var linkMode = false;
  var linkSource = null;
  var svgReady = false;

  var DEFAULT_HINT = "search · hover for detail · red ring = notable · dbl-click a service to collapse · drag (saved) · click to select";

  // BloodHound-style icon nodes: a coloured disc with a white/dark glyph and the label below. Icons
  // are inline SVGs (no network) encoded as data URIs. `#c` is the placeholder colour so one template
  // serves a light glyph (on the dark target) or a dark glyph (on the pale service/finding discs).
  function icon(svg, color) {
    return "data:image/svg+xml;utf8," + encodeURIComponent(svg.replace(/#c/g, color));
  }
  var TPL = {
    target:
      "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'><circle cx='12' cy='12' r='9' fill='none' stroke='#c' stroke-width='2'/><circle cx='12' cy='12' r='4.5' fill='none' stroke='#c' stroke-width='2'/><circle cx='12' cy='12' r='1.5' fill='#c'/></svg>",
    host: "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'><rect x='3' y='4' width='18' height='12' rx='1.5' fill='none' stroke='#c' stroke-width='2'/><line x1='9' y1='20' x2='15' y2='20' stroke='#c' stroke-width='2'/><line x1='12' y1='16' x2='12' y2='20' stroke='#c' stroke-width='2'/></svg>",
    service:
      "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'><rect x='4' y='5' width='16' height='4' rx='1' fill='#c'/><rect x='4' y='11' width='16' height='4' rx='1' fill='#c'/><rect x='4' y='17' width='16' height='2.6' rx='1' fill='#c'/></svg>",
    finding:
      "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'><circle cx='10' cy='10' r='6' fill='none' stroke='#c' stroke-width='2'/><line x1='14.5' y1='14.5' x2='20' y2='20' stroke='#c' stroke-width='2.6'/></svg>",
    credential:
      "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'><circle cx='8' cy='8' r='4.5' fill='none' stroke='#c' stroke-width='2'/><path d='M11 11 L20 20 M18 18 l2 -2 M16 20 l2 -2' stroke='#c' stroke-width='2' fill='none'/></svg>",
    reference:
      "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'><path d='M6 4 h9 a2 2 0 0 1 2 2 v14 H8 a2 2 0 0 1 -2 -2 z' fill='none' stroke='#c' stroke-width='2'/><line x1='6' y1='16' x2='15' y2='16' stroke='#c' stroke-width='2'/></svg>",
    artifact:
      "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'><path d='M6 3 h8 l4 4 v14 H6 z' fill='none' stroke='#c' stroke-width='2'/><path d='M14 3 v4 h4' fill='none' stroke='#c' stroke-width='2'/></svg>",
    note: "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'><path d='M4 20 l1-4 L16 5 l3 3 L8 19 z' fill='none' stroke='#c' stroke-width='2'/></svg>",
  };
  var DARK = "#11111b";
  var LIGHT = "#e6edf3";
  var ICON = {
    target: icon(TPL.target, LIGHT),
    host: icon(TPL.host, DARK),
    service: icon(TPL.service, DARK),
    finding: icon(TPL.finding, DARK),
    credential: icon(TPL.credential, LIGHT),
    reference: icon(TPL.reference, DARK),
    artifact: icon(TPL.artifact, DARK),
    note: icon(TPL.note, DARK),
  };

  var STYLE = [
    {
      selector: "node",
      style: {
        // icon disc + label below (BloodHound-style). Label sits on the dark canvas, so it is light
        // with an outline for legibility over edges. Default glyph is the service icon.
        label: "data(label)",
        "text-wrap": "wrap",
        "text-valign": "bottom",
        "text-halign": "center",
        "text-margin-y": 4,
        "text-max-width": 130,
        color: "#cdd6f4",
        "text-outline-width": 2,
        "text-outline-color": "#181825",
        "font-size": 10,
        width: 34,
        height: 34,
        shape: "ellipse",
        "background-color": "#89b4fa",
        "background-image": ICON.service,
        "background-width": "56%",
        "background-height": "56%",
        "border-width": 2,
        "border-color": "#11111b",
        "border-opacity": 0.55,
      },
    },
    {
      selector: 'node[type="target"]',
      style: {
        "background-color": "#1e3a8a",
        "background-image": ICON.target,
        width: 52,
        height: 52,
        "font-size": 12,
      },
    },
    {
      selector: 'node[type="service"][proto="tcp"]',
      style: { "background-color": "#89b4fa", "background-image": ICON.service },
    },
    {
      selector: 'node[type="service"][proto="udp"]',
      style: { "background-color": "#a6e3a1", "background-image": ICON.service },
    },
    {
      selector: 'node[type="finding"]',
      style: { "background-color": "#f9e2af", "background-image": ICON.finding },
    },
    // pivot topology: a subnet is a compound box that visually contains its hosts; a host is a node
    // reached across a pivot; the pivots-into edge shows which host we tunnelled through.
    {
      selector: 'node[type="subnet"]',
      style: {
        "background-color": "#585b70",
        "background-opacity": 0.12,
        "background-image": "none", // a compound box, not an icon node
        "border-width": 1,
        "border-color": "#9399b2",
        "border-style": "dashed",
        shape: "round-rectangle",
        "text-valign": "top",
        "text-halign": "center",
        "text-margin-y": 0,
        "font-size": 13,
        color: "#bac2de",
        padding: "20px",
      },
    },
    {
      selector: 'node[type="host"]',
      style: {
        "background-color": "#74c7ec",
        "background-image": ICON.host,
        width: 44,
        height: 44,
        "font-size": 11,
      },
    },
    // exploit-db / searchsploit hits are references to READ, not confirmed vulns — colour them
    // distinctly (lavender) and never with the notable ring, so they don't read as danger.
    {
      selector: 'node[category="reference"]',
      style: { "background-color": "#cba6f7", "background-image": ICON.reference },
    },
    {
      selector: 'node[type="artifact"]',
      style: { "background-color": "#fab387", "background-image": ICON.artifact },
    },
    {
      selector: 'node[type="credential"]',
      style: { "background-color": "#f38ba8", "background-image": ICON.credential, width: 40, height: 40 },
    },
    {
      selector: 'node[type="note"]',
      style: { "background-color": "#9399b2", "background-image": ICON.note },
    },
    { selector: "node[status]", style: { "border-width": 3, "border-color": "#f9e2af" } },
    { selector: 'node[status="done"]', style: { "border-color": "#a6e3a1" } },
    { selector: 'node[status="dead-end"]', style: { opacity: 0.45 } },
    { selector: "node[note]", style: { "border-style": "dashed", "border-color": "#cba6f7" } },
    // notable/vulnerable findings (anon access, writable, weak signing…) stand out with a red ring
    {
      selector: "node[notable]",
      style: { "border-width": 5, "border-color": "#f38ba8", "border-style": "double" },
    },
    { selector: "node:selected", style: { "border-width": 4, "border-color": "#cba6f7" } },
    { selector: ".hidden", style: { display: "none" } },
    { selector: ".collapsed-child", style: { display: "none" } }, // double-click drill-down
    // search: bright ring on matches, dim everything else
    {
      selector: ".search-hit",
      style: { "border-width": 6, "border-color": "#f9e2af", "background-blacken": -0.15 },
    },
    { selector: ".search-dim", style: { opacity: 0.12 } },
    {
      selector: "edge",
      style: {
        width: 1.5,
        "line-color": "#585b70",
        "target-arrow-color": "#585b70",
        "target-arrow-shape": "triangle",
        "curve-style": "bezier",
      },
    },
    {
      selector: "edge[label]",
      style: {
        label: "data(label)",
        "font-size": 9,
        color: "#9399b2",
        "text-rotation": "autorotate",
      },
    },
    {
      selector: 'edge[type="relates-to"]',
      style: {
        "line-color": "#cba6f7",
        "target-arrow-color": "#cba6f7",
        "line-style": "dashed",
      },
    },
    {
      selector: 'edge[type="references-credential"]',
      style: { "line-color": "#f38ba8", "target-arrow-color": "#f38ba8" },
    },
    {
      selector: 'edge[type="next-step"]',
      style: { "line-color": "#a6e3a1", "target-arrow-color": "#a6e3a1", "line-style": "dotted" },
    },
    {
      selector: 'edge[type="pivots-into"]',
      style: {
        "line-color": "#f9e2af",
        "target-arrow-color": "#f9e2af",
        "line-style": "dashed",
        width: 2.5,
        "font-size": 10,
        color: "#f9e2af",
      },
    },
  ];

  // A centered message over the canvas — used for "no services yet" and bridge/parse failures, so an
  // empty graph is never a silent blank. Passing "" hides it.
  function setOverlay(text) {
    var el = document.getElementById("cy-overlay");
    if (!el) return;
    el.textContent = text || "";
    el.style.display = text ? "flex" : "none";
  }

  var fcoseReady = false;

  function registerExtensions() {
    if (!svgReady && window.cytoscapeSvg) {
      try {
        cytoscape.use(window.cytoscapeSvg);
        svgReady = true;
      } catch (e) {
        svgReady = false;
      }
    }
    if (!fcoseReady && window.cytoscapeFcose) {
      try {
        cytoscape.use(window.cytoscapeFcose);
        fcoseReady = true;
      } catch (e) {
        fcoseReady = false;
      }
    }
  }

  // does the graph contain subnet compound boxes (a pivot topology)?
  function hasCompound() {
    return cy && cy.nodes('[type="subnet"]').length > 0;
  }

  function runLayout(name) {
    if (!cy) return;
    var opts;
    if (name === "force") {
      // fcose lays out compound (subnet) boxes properly — far better than cose/breadthfirst for the
      // pivot spider-web; fall back to cose when the extension isn't available.
      opts = fcoseReady
        ? { name: "fcose", quality: "default", animate: false, padding: 30, nodeSeparation: 90 }
        : { name: "cose", animate: false, padding: 30 };
    } else if (hasCompound() && fcoseReady) {
      // a pivot topology reads best with fcose even in the "hierarchical" slot — breadthfirst can't
      // keep a subnet's hosts inside its box.
      opts = { name: "fcose", quality: "default", animate: false, padding: 30, nodeSeparation: 90 };
    } else {
      opts = {
        name: "breadthfirst",
        directed: true,
        padding: 30,
        spacingFactor: 1.3,
        roots: "#target",
      };
    }
    cy.layout(opts).run();
    cy.fit(undefined, 40);
  }

  function setLinkMode(on) {
    linkMode = on;
    linkSource = null;
    var button = document.getElementById("link-mode");
    button.style.background = on ? "#cba6f7" : "";
    button.style.color = on ? "#11111b" : "";
    document.getElementById("hint").textContent = on
      ? "LINK MODE: click a source node, then a target — creates a relates-to edge"
      : DEFAULT_HINT;
  }

  function exportImage(format) {
    if (!cy || !bridge) return;
    var data;
    if (format === "svg") {
      if (typeof cy.svg !== "function") return;
      data = cy.svg({ full: true, bg: "#1e1e2e" });
    } else {
      data = cy.png({ output: "base64uri", full: true, scale: 2, bg: "#1e1e2e" });
    }
    bridge.export_image(format, data);
  }

  // Hide/show a node type across the main graph + the minimap; an edge is hidden when either end is.
  function applyFilter() {
    var hidden = {};
    var boxes = document.querySelectorAll("input.filter");
    for (var i = 0; i < boxes.length; i++) {
      if (!boxes[i].checked) hidden[boxes[i].getAttribute("data-type")] = true;
    }
    [cy, mini].forEach(function (graph) {
      if (!graph) return;
      graph.nodes().forEach(function (n) {
        n.toggleClass("hidden", !!hidden[n.data("type")]);
      });
      graph.edges().forEach(function (e) {
        e.toggleClass("hidden", e.source().hasClass("hidden") || e.target().hasClass("hidden"));
      });
    });
  }

  // BloodHound-style search: type "ssh" / "445" / "admin" -> highlight matches, dim the rest, fit.
  function applySearch(query) {
    var q = (query || "").trim().toLowerCase();
    [cy, mini].forEach(function (graph) {
      if (!graph) return;
      graph.nodes().removeClass("search-hit search-dim");
      if (!q) return;
      graph.nodes().forEach(function (n) {
        var hay = [
          n.data("label"),
          n.data("type"),
          n.data("port"),
          n.data("module"),
          n.data("source"),
        ]
          .join(" ")
          .toLowerCase();
        n.addClass(hay.indexOf(q) >= 0 ? "search-hit" : "search-dim");
      });
    });
    if (q && cy) {
      var hits = cy.nodes(".search-hit");
      if (hits.length) cy.fit(hits, 60);
    }
  }

  function updateViewportRect() {
    var rect = document.getElementById("minimap-viewport");
    if (!mini || !rect || !cy) return;
    var z = cy.zoom();
    var pan = cy.pan();
    var w = cy.width();
    var h = cy.height();
    // model-space rectangle currently visible in the main view
    var mx1 = -pan.x / z;
    var my1 = -pan.y / z;
    var mx2 = (w - pan.x) / z;
    var my2 = (h - pan.y) / z;
    var mz = mini.zoom();
    var mp = mini.pan();
    var rx1 = mx1 * mz + mp.x;
    var ry1 = my1 * mz + mp.y;
    var rx2 = mx2 * mz + mp.x;
    var ry2 = my2 * mz + mp.y;
    rect.style.left = Math.min(rx1, rx2) + "px";
    rect.style.top = Math.min(ry1, ry2) + "px";
    rect.style.width = Math.abs(rx2 - rx1) + "px";
    rect.style.height = Math.abs(ry2 - ry1) + "px";
  }

  function buildMinimap(elements) {
    var container = document.getElementById("minimap");
    if (!container) return;
    if (mini) {
      mini.destroy();
      mini = null;
    }
    mini = cytoscape({
      container: container,
      elements: JSON.parse(JSON.stringify(elements)), // clone so the two instances never share state
      style: STYLE,
      userZoomingEnabled: false,
      userPanningEnabled: false,
      boxSelectionEnabled: false,
      autoungrabify: true,
      autounselectify: true,
    });
    window.mini = mini; // exposed for the web inspector / render checks
    cy.nodes().forEach(function (n) {
      var m = mini.getElementById(n.id());
      if (m.length) m.position(n.position());
    });
    mini.fit(undefined, 6);
    // click the minimap to pan the main view there
    mini.on("tap", function (evt) {
      if (!evt.position) return;
      var z = cy.zoom();
      cy.pan({ x: cy.width() / 2 - evt.position.x * z, y: cy.height() / 2 - evt.position.y * z });
    });
    updateViewportRect();
  }

  // hover peek (BloodHound-style). Built with textContent per line — never innerHTML — so a banner
  // with HTML in it can't inject, and it NEVER reads data('secret'): creds show only user@domain.
  function showTip(node) {
    var tip = document.getElementById("node-tip");
    if (!tip || !cy) return;
    var d = node.data();
    var rows = [["", String(d.label || d.id || "")]];
    if (d.type) rows.push(["type", d.type]);
    if (d.port) rows.push(["port", d.port + "/" + (d.proto || "")]);
    if (d.cidr) rows.push(["subnet", d.cidr]);
    if (d.module) rows.push(["module", d.module]);
    if (d.source) rows.push(["source", d.source]);
    if (d.category) rows.push(["category", d.category]);
    if (d.status) rows.push(["status", d.status]);
    if (d.note) rows.push(["note", d.note]);
    tip.textContent = "";
    rows.forEach(function (r) {
      var line = document.createElement("div");
      line.textContent = r[0] ? r[0] + ": " + r[1] : r[1];
      if (!r[0]) line.style.fontWeight = "bold";
      tip.appendChild(line);
    });
    var rect = document.getElementById("cy").getBoundingClientRect();
    var rp = node.renderedPosition();
    var bb = node.renderedBoundingBox();
    tip.style.left = rect.left + rp.x + 14 + "px";
    tip.style.top = rect.top + bb.y1 - 6 + "px";
    tip.style.display = "block";
  }
  function hideTip() {
    var tip = document.getElementById("node-tip");
    if (tip) tip.style.display = "none";
  }

  function render(elements) {
    registerExtensions();
    // rebuild from scratch each refresh — destroy the old instance so handlers/state don't stack up
    if (cy) {
      cy.destroy();
      cy = null;
    }
    var nodeCount = (elements && elements.nodes ? elements.nodes.length : 0);
    // a lone target node (no services yet) is effectively empty — tell the user how to populate it
    var serviceCount = 0;
    if (elements && elements.nodes) {
      for (var k = 0; k < elements.nodes.length; k++) {
        var d = elements.nodes[k].data || {};
        if (d.type && d.type !== "target") serviceCount++;
      }
    }
    if (!nodeCount) {
      setOverlay("No project data yet. Open a project and run Full Recon to build the graph.");
    } else if (!serviceCount) {
      setOverlay("No services discovered yet — click “Run Full Recon” to scan the target.");
    } else {
      setOverlay("");
    }

    cy = cytoscape({
      container: document.getElementById("cy"),
      elements: elements,
      style: STYLE,
    });
    window.cy = cy; // exposed for the web inspector / render checks

    var hasSaved = (elements.nodes || []).some(function (n) {
      return n.position;
    });
    if (hasSaved) cy.fit(undefined, 40);
    else runLayout("hier");

    cy.on("tap", "node", function (evt) {
      var id = evt.target.id();
      if (linkMode) {
        if (!linkSource) {
          linkSource = id;
          document.getElementById("hint").textContent = "LINK MODE: now click the target node";
        } else {
          if (bridge && id !== linkSource) {
            bridge.add_user_edge(linkSource, id, "");
            cy.add({
              data: { id: "live-" + linkSource + "-" + id, source: linkSource, target: id, type: "relates-to" },
            });
          }
          setLinkMode(false);
        }
        return; // link mode swallows the tap — no detail sidebar
      }
      if (bridge) bridge.node_clicked(id, JSON.stringify(evt.target.data()));
    });

    // double-click a service to drill down: collapse/expand its findings & artifacts. Uses its own
    // class (independent of the type-filter's `hidden`) so the two never clobber each other.
    cy.on("dbltap", 'node[type="service"]', function (evt) {
      var svc = evt.target;
      var collapsed = !svc.data("collapsed");
      svc.data("collapsed", collapsed);
      svc.outgoers("node").toggleClass("collapsed-child", collapsed);
    });

    cy.on("dragfree", "node", function () {
      if (!bridge) return;
      var positions = {};
      cy.nodes().forEach(function (n) {
        var p = n.position();
        positions[n.id()] = [Math.round(p.x), Math.round(p.y)];
      });
      bridge.save_positions(JSON.stringify(positions));
    });

    cy.on("pan zoom resize", updateViewportRect);
    cy.on("mouseover", "node", function (evt) {
      showTip(evt.target);
    });
    cy.on("mouseout", "node", hideTip);
    cy.on("pan zoom drag", hideTip);

    document.getElementById("layout-hier").onclick = function () {
      runLayout("hier");
    };
    document.getElementById("layout-force").onclick = function () {
      runLayout("force");
    };
    document.getElementById("fit").onclick = function () {
      cy.fit(undefined, 40);
    };
    document.getElementById("link-mode").onclick = function () {
      setLinkMode(!linkMode);
    };
    document.getElementById("export-png").onclick = function () {
      exportImage("png");
    };
    document.getElementById("export-svg").onclick = function () {
      exportImage("svg");
    };
    var boxes = document.querySelectorAll("input.filter");
    for (var i = 0; i < boxes.length; i++) boxes[i].onchange = applyFilter;
    var search = document.getElementById("search");
    if (search)
      search.oninput = function () {
        applySearch(this.value);
      };

    buildMinimap(elements);
  }

  // (Re)fetch the current profile's elements from Qt and render them in place. Exposed to Qt so a
  // finished scan can refresh the canvas without a full page reload (graph_view.py calls this).
  function refresh() {
    if (!bridge) return;
    bridge.get_data(function (json) {
      var elements;
      try {
        elements = JSON.parse(json);
      } catch (e) {
        setOverlay("Graph data could not be read.");
        return;
      }
      render(elements);
    });
  }
  window.oscpRefresh = refresh;

  function boot(attempt) {
    attempt = attempt || 0;
    if (typeof QWebChannel === "undefined" || !window.qt || !qt.webChannelTransport) {
      // the transport is injected slightly after DOM load — retry briefly before giving up
      if (attempt < 40) {
        setTimeout(function () {
          boot(attempt + 1);
        }, 50);
        return;
      }
      setOverlay(
        "Graph bridge unavailable in this environment. The recon summary on the left still lists " +
          "every discovered service, and status / notes work there."
      );
      return;
    }
    new QWebChannel(qt.webChannelTransport, function (channel) {
      bridge = channel.objects.bridge;
      refresh();
    });
  }

  if (window.qt && window.qt.webChannelTransport) boot(0);
  else window.addEventListener("load", function () { boot(0); });
})();
