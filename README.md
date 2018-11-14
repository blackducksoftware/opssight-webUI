# opssight-webUI
A web-based interface for exploring OpsSight output

# Goals
v0.1 is an HTML5 webpage that provides several different visualizations for pre-generated scan results in OpsSight

- [x] Image view shows scan results by imgaeSHA and the name associated with it
- [ ] Allow flipping between imageSHA, truncated imageSHA, full repository name, and repository basename
- [ ] Hierarchical view lets you explore results aggregates: Cluster -> Node | Namespace -> Pod -> Container -> ¿Layer eventually?
- [ ] Hierarchical views get a few different zoomable visualizations to flip between
- [ ] Hierarchical views get a parallel view that looks like a file manager - mainly because any visualization breaks down when you have enough entries at some level

v0.2 has some visibility and usability improvements
- [ ] Image table headers don't stretch the width
- [ ] Image table columns get a fill proportional to the number as a fraction of the sum OR the highest
- [ ] Leaf nodes in the tree have an adjustable minimum size
- [ ] CSS that makes it look like other BlackDuck webUIs
- [ ] Categories and severities are multi-selectable and the sum is the output
