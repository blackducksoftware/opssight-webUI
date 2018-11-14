# opssight-webUI
A web-based interface for exploring OpsSight output

# Demo
[https://blackducksoftware.github.io/opssight-webUI/](https://blackducksoftware.github.io/opssight-webUI/)

# Goals
v0.1 is an HTML5 webpage that provides several different visualizations for pre-generated scan results in OpsSight

- ☑ Image view shows scan results by imgaeSHA and the name associated with it
- ☐ Allow flipping between imageSHA, truncated imageSHA, full repository name, and repository basename
- ☐ Hierarchical view lets you explore results aggregates: Cluster -> Node | Namespace -> Pod -> Container -> ¿Layer eventually?
- ☐ Hierarchical views get a few different zoomable visualizations to flip between
- ☐ Hierarchical views get a parallel view that looks like a file manager - mainly because any visualization breaks down when you have enough entries at some level
- ☐ CSS that makes it look like other BlackDuck webUIs
