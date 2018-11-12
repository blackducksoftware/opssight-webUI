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

function renderViews(){
  // Image view:
  var htmlText = "";
  var selectionReady = true;
  for(s in selectors){
    if(s in selection){
      // console.log(s + ' in ' + selection)
    }else{
      // console.log(s + ' not in ' + selection)
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
      var statusCounts = 
        model.
        CoreModel.
        Images[i].
        ScanResults.
        RiskProfile.
        Categories[selection["category"]].
        StatusCounts[selection["severity"]];
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

  // // Node view:
  var htmlText = "";
  if(pod_to_nodeMapping === ""){
    htmlText = "<pre>pod-to-node mapping hasn't loaded yet</pre>";
  }else{
    htmlText = ""
    console.log(window.innerWidth, window.innerHeight);
    htmlText += 
      '<svg width="' +
      (window.innerHeight * 0.95) + 
      '" height="' + 
      (window.innerHeight * 0.95) + 
      '" id="circleView_svg" onload="circleView();">' + 
      '</svg>';
		htmlText +=
      '<svg width="' +
      (window.innerWidth * 0.95) + 
      '" height="' + 
      (window.innerHeight * 0.95) + 
      '" id="squareView_svg" onload="squareView();">' + 
      '</svg>';
  }
  document.getElementById('nodeView').innerHTML = htmlText;
  treeForD3 = {};
  treeForD3["name"] = "cluster";
  treeForD3["children"] = [];
  // console.log(pod_to_nodeMapping);
  var nodeIndex = 0;
  for(var n in pod_to_nodeMapping){
    var treeNode = {};
    treeNode["name"] = "node " + n;
    treeNode["children"] = [];
    treeForD3["children"].push(treeNode);
    var podIndex = 0;
    for(var p in pod_to_nodeMapping[n]){
      var treePod = {};
      treePod["name"] = "pod " + p;
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
          treeContainer["name"] = "container " + 
            model.
            CoreModel.
            Pods.
            coreModelPodName.
            Containers[c].
            Name;
          treeContainer["size"] = 1;
          treeContainer["children"][nodeIndex]["children"][podIndex]["children"].push(treeContainer);
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
  console.log(JSON.stringify(model.CoreModel.Pods))
  for(p in 
    model.
    CoreModel.
    Pods)
  {
    noNameSpace = p.split('/')[1];
    console.log(noNameSpace, nodeMapPodName)
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
