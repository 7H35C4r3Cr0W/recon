// Renders the profile graph with Cytoscape.js and talks to the Qt GraphBridge over QWebChannel.
// Node/edge colors follow CLAUDE.md §16. No network — cytoscape.min.js / cytoscape-svg.js are vendored,
// qwebchannel.js is served by Qt from qrc://. The minimap is a second locked Cytoscape overview (no
// jQuery-dependent navigator extension).
(function () {
  "use strict";
  var cy = null;
  var mini = null;
  var bridge = null;
  var linkMode = false;
  var linkSource = null;
  var svgReady = false;

  var DEFAULT_HINT = "search to highlight · red ring = notable finding · drag nodes (saved) · click for detail";

  var STYLE = [
    {
      selector: "node",
      style: {
        label: "data(label)",
        "text-wrap": "wrap",
        "text-valign": "center",
        "text-halign": "center",
        "text-max-width": 150,
        color: "#11111b",
        "font-size": 11,
        width: "label",
        height: "label",
        padding: "8px",
        shape: "round-rectangle",
        "background-color": "#89b4fa",
      },
    },
    {
      selector: 'node[type="target"]',
      style: { "background-color": "#1e3a8a", color: "#e0e7ff", shape: "ellipse", "font-size": 14 },
    },
    { selector: 'node[type="service"][proto="tcp"]', style: { "background-color": "#89b4fa" } },
    { selector: 'node[type="service"][proto="udp"]', style: { "background-color": "#a6e3a1" } },
    { selector: 'node[type="finding"]', style: { "background-color": "#f9e2af" } },
    { selector: 'node[type="artifact"]', style: { "background-color": "#fab387" } },
    {
      selector: 'node[type="credential"]',
      style: { "background-color": "#f38ba8", color: "#e0e7ff" },
    },
    { selector: 'node[type="note"]', style: { "background-color": "#9399b2" } },
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
  ];

  function registerExtensions() {
    if (!svgReady && window.cytoscapeSvg) {
      try {
        cytoscape.use(window.cytoscapeSvg);
        svgReady = true;
      } catch (e) {
        svgReady = false;
      }
    }
  }

  function runLayout(name) {
    if (!cy) return;
    var opts =
      name === "force"
        ? { name: "cose", animate: false, padding: 30 }
        : { name: "breadthfirst", directed: true, padding: 30, spacingFactor: 1.3, roots: "#target" };
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
    if (!mini || !rect) return;
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

  function render(elements) {
    registerExtensions();
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

  function boot() {
    if (typeof QWebChannel === "undefined" || !window.qt || !qt.webChannelTransport) {
      return;
    }
    new QWebChannel(qt.webChannelTransport, function (channel) {
      bridge = channel.objects.bridge;
      bridge.get_data(function (json) {
        render(JSON.parse(json));
      });
    });
  }

  if (window.qt && window.qt.webChannelTransport) boot();
  else window.addEventListener("load", boot);
})();
