var selectors = {};
// First one is default
selectors["organization"] = [
  "node",
  "namespace"
];
selectors["category"] = [
  "VULNERABILITY", 
  "ACTIVITY", 
  "LICENSE", 
  "OPERATIONAL", 
  "VERSION"
];
selectors["severity"] = [
  "HIGH", 
  "LOW", 
  "MEDIUM", 
  "OK", 
  "UNKNOWN"
];
selectors["image id"] = [
  "repo basename",
  "repo full name",
  "truncated SHA",
  "full SHA"
];

var selection = {};

var pod_to_nodeMapping = "";

function main() {
  for(var k in selectors) {
    makeSelector(k, selectors[k]);
    selection = changeSelection(k, selectors[k][0]);
  }
  renderViews();
}

function makeSelector(name, options){
  selString = 'selector-' + name;
  var divString = '<div id="' + selString + '"></div>';
  document.getElementById('selectorsRoot').innerHTML += divString;
  document.getElementById(selString).innerHTML += name + ": ";
  for(var i in options){
    var optString = selString + '-' + options[i];
    var buttonString = [
      '<input type="button" id="',
      optString,
      '" value="',
      options[i],
      '" onclick="changeSelection(\'',
      name,
      '\', \'',
      options[i],
      '\');" />'
    ].join('');
    document.getElementById(selString).innerHTML += buttonString;
  }
}

function changeSelection(name, option){
  selection[name] = option;
  updateSelector(name, selection, selectors);
  renderViews();
  return selection;
}

function updateSelector(name, selection){
  selClass = "selected-option";
  for(var s in selectors[name]){
    var id = "selector-" + name + "-" + selectors[name][s];
    if(selection[name] == selectors[name][s]){
      document.getElementById(id).classList.add(selClass);
    }else{
      document.getElementById(id).classList.remove(selClass);
    }
  }
}

function getVulnsFromImageSHA(imageSHA){
  var count = 
    model.
    CoreModel.
    Images[imageSHA].
    ScanResults.
    RiskProfile.
    Categories[selection["category"]].
    StatusCounts[selection["severity"]];
  return count;
}

function truncateSha(imageSHA){
  var truncated = 
    imageSHA.substring(0, 4) + 
    "\u2026" + 
    imageSHA.substring(60, 64);
  return truncated;
}

function repoNameOfImageSHA(imageSHA){
  var repoName = 
    model.
    CoreModel.
    Images[imageSHA].
    RepoTags[0].
    Repository;
  return repoName;
}

function basenameOfRepoName(repoName){
  var baseName = repoName.split("/").pop();
  return baseName;
}

function renderViews(){
  var htmlText = "";
  var selectionReady = true;
  for(s in selectors){
    if(!(s in selection)){
      selectionReady = false;
    }
  }
  if(selectionReady === false){
    htmlText = "Selections aren't ready, can't render yet.";
    document.getElementById('message').innerHTML = htmlText;
    return;
  }else{
    htmlText = ""
    document.getElementById('message').innerHTML = htmlText;
  }

  // Image view:
  var htmlText = "";
  htmlText = [
    "<table>", 
    "<th>Image</th>", 
    "<th>Instances</th>",
    "<th>" + selection["severity"] + ' severity ' + selection["category"] + " count</th>", 
    "<th>Production datacenter impact factor</th>"
  ].join('');
  for(var i in model.CoreModel.Images){
    var displayName = {}
    displayName["full SHA"] = i;
    displayName["truncated SHA"] = truncateSha(displayName["full SHA"]);
    displayName["repo full name"] = repoNameOfImageSHA(displayName["full SHA"]);
    displayName["repo basename"] = basenameOfRepoName(displayName["repo full name"]);
    nameToDisplay = displayName[selection["image id"]];
    var instances = countImageInstances(i, model.CoreModel.Pods);
    var statusCounts = getVulnsFromImageSHA(i);
    var product = instances * statusCounts;
    htmlText += "<tr>";
    htmlText += "<td class='monospace'>" + nameToDisplay + "</td>";
    htmlText += "<td>" + instances + "</td>";
    htmlText += "<td>" + statusCounts + "</td>";
    htmlText += "<td>" + product + "</td>";
    htmlText += "</tr>";
  }
  htmlText += "</table>";
  document.getElementById('imageView').innerHTML = htmlText;

  // Hierarchical view
  var htmlText = "";
  if(pod_to_nodeMapping === ""){
    htmlText = "<pre>pod-to-node mapping hasn't loaded yet</pre>";
  }else{
    var dimensions = Math.min(window.innerHeight, document.getElementsByTagName("body")[0].clientWidth);
    htmlText = ""
    htmlText += 
      '<svg width="' +
      dimensions + 
      '" height="' + 
      dimensions + 
      '" id="circleView_svg" onload="circleView();">' + 
      '</svg>';
		htmlText +=
      '<svg width="' +
      dimensions + 
      '" height="' + 
      dimensions + 
      '" id="squareView_svg" onload="squareView();">' + 
      '</svg>';
  }
  document.getElementById('nodeView').innerHTML = htmlText;
  circleView(makeD3Cluster());
}

function makeD3Cluster(){
  cluster = {}
  cluster["name"] = "cluster";
  cluster["children"] = [];
  if(selection["organization"] == "node"){
    for(var nodeName in pod_to_nodeMapping){
      cluster["children"].push(makeD3Node(nodeName));
    }
  }
  if(selection["organization"] == "namespace"){
    nameSpaces = nameSpacesOfAllPods(model.CoreModel.Pods);
    for(var nameSpaceName in nameSpaces){
      cluster["children"].push(makeD3NameSpace(nameSpaces, nameSpaceName));
    }
  }
  return cluster;
}

function makeD3Node(nodeName){
  var node = {};
  node["name"] = nodeName;
  node["children"] = [];
  for(var podName in pod_to_nodeMapping[nodeName]){
    podName = coreModelPodName(podName);
    node["children"].push(makeD3Pod(podName));
  }
  return node;
}

function makeD3NameSpace(nameSpaces, nameSpaceName){
  var nameSpace = {}
  nameSpace["name"] = nameSpaceName;
  nameSpace["children"] = [];
  for(var podName in nameSpaces[nameSpaceName]){
    nameSpace["children"].push(makeD3Pod(podName));
  }
  return nameSpace;
}

function nameSpacesOfAllPods(allPods){
  nameSpaces = {};
  for(pod in allPods){
    var nameSpace = pod.split("/")[0];
    if(!(nameSpace in nameSpaces)){
      nameSpaces[nameSpace] = {};
    }
    nameSpaces[nameSpace][pod] = undefined;
  }
  return nameSpaces;
}

function makeD3Pod(podName){
  var pod = {};
  pod["name"] = podName;
  pod["children"] = [];
  for(var containerIndex in 
    model.
    CoreModel.
    Pods[podName].
    Containers)
  {
    pod["children"].push(makeD3Container(podName, containerIndex));
  }
  return pod;
}

function makeD3Container(podName, containerIndex){
  var container = {};
  container["name"] = 
    model.
    CoreModel.
    Pods[podName].
    Containers[containerIndex].
    Name;
  var imageSHA = 
    model.
    CoreModel.
    Pods[podName].
    Containers[containerIndex].
    Image["Sha"];
  container["size"] = getVulnsFromImageSHA(imageSHA);
  return container;
}

function coreModelPodName(nodeMapPodName){
  for(p in 
    model.
    CoreModel.
    Pods)
  {
    noNameSpace = p.split('/')[1];
    if(noNameSpace == nodeMapPodName){
      return p;
    }
  }
  return "I have no idea what this pod's namespace is"
}

function countImageInstances(imageSHA, pods){
  var instanceCount = 0;
  for(p in pods){
    for(c in model.CoreModel.Pods[p].Containers){
      if(model.CoreModel.Pods[p].Containers[c].Image.Sha == imageSHA){
        instanceCount++;
      }
    }
  }
  return instanceCount;
}

var xhr = new XMLHttpRequest();
xhr.open("GET", "pod-to-node.mapping.txt", true);
xhr.onload = function (e) {
  if (xhr.readyState === 4) {
    if (xhr.status === 200) {
      pod_to_nodeMapping = xhr.responseText;
      pod_to_nodeMapping = pod_to_nodeParse(pod_to_nodeMapping);
      // console.log(pod_to_nodeMapping);
      renderViews();
    } else {
      console.error(xhr.statusText);
    }
  }
};
xhr.onerror = function (e) {
  console.error(xhr.statusText);
};
xhr.send(null);

function pod_to_nodeParse(text){
  // console.log(pod_to_nodeMapping);
  pod_to_nodeMapping = {};
  var lines = text.split('\n');
  for(l in lines){
    if(lines[l] === ""){continue;}
    if(l == 0){continue;}
    var words = lines[l].split(/\s+/);
    // console.log(words);
    if(words[2] in pod_to_nodeMapping){
      // console.log(words[2] + " already in");
    }else{
      pod_to_nodeMapping[words[2]] = {};
      // console.log(JSON.stringify(pod_to_nodeMapping));
    }
    pod_to_nodeMapping[words[2]][words[0]] = words[1];
    // console.log(JSON.stringify(pod_to_nodeMapping));
    // console.log(pod_to_nodeMapping);
  }
  return pod_to_nodeMapping;
}
