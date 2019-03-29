console.log('Background Running')
var url_log = ["https://www.google.com/","https://drive.google.com/"]
var url_type_log = ["Legitimate","Legitimate"]
var count = [1,1]
chrome.tabs.onUpdated.addListener( function (tabId, changeInfo, tab) {
  if (changeInfo.status == "loading" && tab.active && (tab.url.substring(0,5)=="http:"||tab.url.substring(0,5)=="https") ) {
  	//console.log(tab.url);
    var url = tab.url;
    index = -1
    if(!url.includes('@')){
        var n = url.indexOf("/",8);
        url = url.substring(0,n+1);
        index = url_log.indexOf(url);
    }
    if(index!=-1){
        resp = url_type_log[index] 
        //console.log(url_log)
        //console.log(url_type_log)
        if(resp == "Phishy"){
            count[index]++;
            if (count[index]>1){  
              url_type_log[index] = "Suspicious"
            }
            else{
              chrome.tabs.update(tab.id, {url: "file:///Users/mukul/Downloads/ChromeExtension2/warning.html"});
            }  
            chrome.pageAction.setIcon({
              path:"phishy.png",
              tabId: tab.id
            });           
          }
          else if(resp == "Legitimate"){
            chrome.pageAction.setIcon({
              path:"legitimate.png",
              tabId: tab.id
            });
          }
          else{
            chrome.pageAction.setIcon({
              path:"suspicious.png",
              tabId: tab.id
            });
          }  
    }
    else{
      $.ajax({
        url: "http://localhost:5000/predict",
        type: "POST",
        data:{ 
          url: url }   
        }).done(function(resp){
            if(resp == "Phishy"){
                 url_log.push(url)
                url_type_log.push("Phishy")
                count.push(1);
                chrome.tabs.update(tab.id, {url: "file:///Users/mukul/Downloads/ChromeExtension2/warning.html"});
                chrome.pageAction.setIcon({
                  path:"phishy.png",
                  tabId: tab.id
                });           
              }
              else if(resp == "Legitimate"){
                var n = url.indexOf("/",8);
                url = url.substring(0,n+1);
                url_log.push(url);
                count.push(1);
                url_type_log.push("Legitimate");
                chrome.pageAction.setIcon({
                  path:"legitimate.png",
                  tabId: tab.id
                });
              }
              else{
                url_log.push(url);
                url_type_log.push("Suspicious");
                count.push(1);
                chrome.pageAction.setIcon({
                  path:"suspicious.png",
                  tabId: tab.id
                });
              }
        });
    }
  }
})
