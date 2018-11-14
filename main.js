var selectors = {};
// First one is default
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
]
selectors["organization"] = [
  "node",
  "namespace"
]

var selection = {};

var pod_to_nodeMapping = "";

function main() {
  for(var k in selectors) {
    makeSelector(k, selectors[k]);
    selection = changeSelection(k, selectors[k][0]);
  }
  settingsReady = true;
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

function renderViews(){
  // Image view:
  var htmlText = "";
  var selectionReady = true;
  for(s in selectors){
    if(!(s in selection)){
      selectionReady = false;
    }
  }
  if(selectionReady === false){
    htmlText = "Trying to render Image view but settings aren't ready";
  }else{
    htmlText = [
      "<table>", 
      "<th>Image</th>", 
      "<th>Instances</th>",
      "<th>" + selection["severity"] + ' severity ' + selection["category"] + " count</th>", 
      "<th>Production datacenter impact factor</th>"
    ].join('');
    for(var i in model.CoreModel.Images){
      var instances = countImageInstances(i, model.CoreModel.Pods);
      var statusCounts = getVulnsFromImageSHA(i);
      var product = instances * statusCounts;
      htmlText += "<tr>";
      htmlText += "<td class='monospace'>" + i + "</td>";
      htmlText += "<td>" + instances + "</td>";
      htmlText += "<td>" + statusCounts + "</td>";
      htmlText += "<td>" + product + "</td>";
      htmlText += "</tr>";
    }
    htmlText += "</table>";
  }
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
  treeForD3 = {};
  treeForD3["name"] = "cluster";
  treeForD3["children"] = [];
  var nodeIndex = 0;
  for(var n in pod_to_nodeMapping){
    var treeNode = {};
    treeNode["name"] = n;
    treeNode["children"] = [];
    treeForD3["children"].push(treeNode);
    var podIndex = 0;
    for(var p in pod_to_nodeMapping[n]){
      var treePod = {};
      treePod["name"] = p;
      if(coreModelPodName(p) == "I have no idea what this pod's namespace is"){
        treePod["size"] = 1;
        console.log("============failed to find" + p);
      }else{
        treePod["children"] = [];
        var containerIndex = 0;
        for(var c in 
          model.
          CoreModel.
          Pods[coreModelPodName(p)].
          Containers)
        {
          var treeContainer = {};
          console.log(model.CoreModel.Pods, coreModelPodName(p))
          treeContainer["name"] = 
            model.
            CoreModel.
            Pods[coreModelPodName(p)].
            Containers[c].
            Name;
          var imageSHA = 
            model.
            CoreModel.
            Pods[coreModelPodName(p)].
            Containers[c].
            Image["Sha"];
          treeContainer["size"] = getVulnsFromImageSHA(imageSHA);
          console.log(imageSHA, treeContainer["size"]);
          console.log(treeForD3)
          treePod["children"].push(treeContainer);
          containerIndex++;
        }
      }
      treeForD3["children"][nodeIndex]["children"].push(treePod);
      podIndex++;
    }
    nodeIndex++;
  }
  circleView(treeForD3);
  // squareView(treeForD3);
  // nodeIssues = {}
  // for(n in nodes){
  //   nodeIssues[n]
  //   for(p in pods){
  //     if(pod[p] in n){
  //       nodaddIssues(imageOfPod(pod[p]), 

  // Hierarchical list
  // make an alt model
  //
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
