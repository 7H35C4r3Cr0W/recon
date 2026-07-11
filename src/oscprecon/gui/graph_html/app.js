// Renders the profile graph with Cytoscape.js and talks to the Qt GraphBridge over QWebChannel.
// Node/edge colors follow CLAUDE.md §16. No network — cytoscape.min.js is vendored, qwebchannel.js
// is served by Qt from qrc://.
(function () {
  "use strict";
  var cy = null;
  var bridge = null;

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
    {
      selector: "node[status]",
      style: { "border-width": 3, "border-color": "#f9e2af" },
    },
    { selector: 'node[status="done"]', style: { "border-color": "#a6e3a1" } },
    { selector: 'node[status="dead-end"]', style: { opacity: 0.45 } },
    { selector: "node[note]", style: { "border-style": "dashed", "border-color": "#cba6f7" } },
    { selector: "node:selected", style: { "border-width": 4, "border-color": "#cba6f7" } },
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
      // only edges that actually carry a label get one (avoids Cytoscape's "no mapping" warning)
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

  function runLayout(name) {
    if (!cy) return;
    var opts =
      name === "force"
        ? { name: "cose", animate: false, padding: 30 }
        : {
            name: "breadthfirst",
            directed: true,
            padding: 30,
            spacingFactor: 1.3,
            roots: "#target",
          };
    cy.layout(opts).run();
    cy.fit(undefined, 40);
  }

  function render(elements) {
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
      if (bridge) bridge.node_clicked(evt.target.id());
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

    document.getElementById("layout-hier").onclick = function () {
      runLayout("hier");
    };
    document.getElementById("layout-force").onclick = function () {
      runLayout("force");
    };
    document.getElementById("fit").onclick = function () {
      cy.fit(undefined, 40);
    };
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
