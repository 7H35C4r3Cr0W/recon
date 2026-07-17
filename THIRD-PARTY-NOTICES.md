# Third-party notices

Nabu (`oscp-recon`) is licensed under the MIT License (see `LICENSE`). It bundles the following
third-party components, which remain under their own licenses.

## Vendored JavaScript (offline graph view)

Under `src/oscprecon/gui/graph_html/`. All MIT-licensed; shipped so the graph renders with no CDN
or network access at runtime.

| File | Component | Upstream | License |
| --- | --- | --- | --- |
| `cytoscape.min.js` | Cytoscape.js | https://github.com/cytoscape/cytoscape.js | MIT © The Cytoscape Consortium |
| `cytoscape-fcose.js` | cytoscape.js-fcose (layout) | https://github.com/iVis-at-Bilkent/cytoscape.js-fcose | MIT © i-Vis Lab, Bilkent University |
| `cose-base.js` | cose-base | https://github.com/iVis-at-Bilkent/cose-base | MIT © i-Vis Lab, Bilkent University |
| `layout-base.js` | layout-base | https://github.com/iVis-at-Bilkent/layout-base | MIT © i-Vis Lab, Bilkent University |
| `cytoscape-svg.js` | cytoscape-svg (PNG/SVG export) | https://github.com/kinular/cytoscape-svg | MIT |

`qwebchannel.js` is provided at runtime by Qt/PySide6 (LGPL) and is not vendored in this repository.

The MIT license text (applies to each component above):

```
Permission is hereby granted, free of charge, to any person obtaining a copy of this software and
associated documentation files (the "Software"), to deal in the Software without restriction,
including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense,
and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions: The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software. THE SOFTWARE IS PROVIDED "AS IS",
WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED...
```

## Vendored documentation snapshot

Under `src/oscprecon/references/hacktricks/` — a build-time snapshot of the open-source **HackTricks**
network-services-pentesting pages (https://github.com/HackTricks-wiki/hacktricks), used for offline,
finding-aware reference rendering.

- **License:** Creative Commons **Attribution-NonCommercial-ShareAlike 4.0** (CC BY-NC-SA 4.0).
- Attribution and the license are preserved with the snapshot; the content is displayed, never
  modified in place, and is refreshed only by a maintainer-run vendoring script (never at runtime).

## Runtime dependencies

Nabu depends on PySide6 (LGPL/commercial, Qt for Python), Typer, Jinja2, and PyYAML — installed via
`uv`, not vendored. See `pyproject.toml`.
