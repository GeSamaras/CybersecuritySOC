[**The official description**](https://www.autopsy.com/): "_Autopsy is the premier open source forensics platform which is fast, easy-to-use, and capable of analysing all types of mobile devices and digital media. Its plug-in architecture enables extensibility from community-developed or custom-built modules. Autopsy evolves to meet the needs of hundreds of thousands of professionals in law enforcement, national security, litigation support, and corporate investigation._"

**Workflow Overview**  

Before diving into Autopsy and analysing data, there are a few steps to perform; such as identifying the data source and what Autopsy actions to perform with the data source. 

Basic workflow:

1. Create/open the case for the data source you will investigate
2. Select the data source you wish to analyse
3. Configure the ingest modules to extract specific artefacts from the data source
4. Review the artefacts extracted by the ingest modules
5. Create the report

Case Analysis | Create a New Case  

To prepare a new case investigation, you need to create a case file from the data source. When you start Autopsy, there will be three options. You can create a new case file using the **"New Case"** option. Once you click on the "New Case" option, the **Case Information** menu opens**,** where information about the case is populated.

- **Case Name**: The name you wish to give to the case
- **Base Directory**: The root directory that will store all the files specific to the case (the full path will be displayed)
- **Case Type**: Specify whether this case will be local (**Single-user**) or hosted on a server where multiple analysts can review (**Multi-user**)

**Ingest Modules**

Essentially **Ingest Modules** are Autopsy plug-ins. Each Ingest Module is designed to analyse and retrieve specific data from the drive. You can configure Autopsy to run specific modules during the source-adding stage or later by choosing the target data source available on the dashboard. By default, the Ingest Modules are configured to run on All Files, Directories, and Unallocated Space. You can change this setting during the module selecting step. You can track the process with the bar appearing in the lower right corner.

The below screenshots simulate mentioned two different approaches to using ingest modules. Note that using ingest modules requires time to implement. Therefore we will not cover ingest modules in this room.

Note: Autopsy adds metadata about files to the local database, not the actual file contents. 

**Configuring ingest modules while adding data sources:**  
  

![Autopsy - Configuring ingest module while adding data source](https://assets.tryhackme.com/additional/autopsy/autopsy-configure-modules.png)

**Using ingest modules after adding data sources:**

1. Open the "Run Ingest Modules" menu by right-clicking on the data source.
2. Choose the modules to implement and click on the finish button.
3. Track the progress of implementation.

![Autopsy - Use ingest module after adding data sources](https://tryhackme-images.s3.amazonaws.com/user-uploads/6131132af49360005df01ae3/room-content/04138be7675286ea5f9066a893c0b199.png)  

The results of any Ingest Module you select to run against a data source will populate the Results node in the Tree view, which is the left pane of the Autopsy user interface. Below is an example of using the **"Interesting Files Identifier"** ingest module. Note that the results depend on the dataset. If you choose a module to retrieve specific data that is unavailable in the drive, there will be no results.

![Autopsy - Ingest module sample result](https://tryhackme-images.s3.amazonaws.com/user-uploads/6131132af49360005df01ae3/room-content/9ee9f606ea3444fd04c45b15c2c7f819.png)  

Drawing the attention back to the Configure Ingest Modules window, notice that some Ingest Modules have per-run settings and some do not. For example, the Keyword Search Ingest Module does not have per-run settings. In contrast, the Interesting Files Finder Ingest Module does. The yellow triangle represents the "per-run settings option".

As Ingest Modules run, alerts may appear in the **Ingest Inbox**. Below is an example of the Ingest Inbox after a few Ingest Modules have completed running. 

![Autopsy - Ingest inbox](https://tryhackme-images.s3.amazonaws.com/user-uploads/6131132af49360005df01ae3/room-content/212c83e75693ce2d8f485633a11dd697.png)


To learn more about Ingest Modules, read Autopsy documentation [here](http://sleuthkit.org/autopsy/docs/user-docs/4.12.0/ingest_page.html).

**The User Interface I**

Let's look at the Autopsy user interface, which is comprised of 5 primary areas: 

**Tree Viewer**

![Autopsy - Tree view](https://assets.tryhackme.com/additional/autopsy/autopsy-tree-view.png)

The **Tree Viewer** has **five top-level nodes**:

- **Data Sources** - all the data will be organised as you would typically see it in a normal Windows File Explorer. 
- **Views** - files will be organised based on file types, MIME types, file size, etc. 
- **Results** - as mentioned earlier, this is where the results from Ingest Modules will appear. 
- **Tags** - will display files and/or results that have been tagged (read more about tagging [here](http://sleuthkit.org/autopsy/docs/user-docs/4.12.0/tagging_page.html)).
- **Reports** - will display reports either generated by modules or the analyst (read more about reporting [here](http://sleuthkit.org/autopsy/docs/user-docs/4.12.0/reporting_page.html)).

Refer to the Autopsy documentation on the **Tree Viewer** for more information [here](http://sleuthkit.org/autopsy/docs/user-docs/4.12.0/tree_viewer_page.html). 

**Result Viewer**

**Note**: Don't confuse the Results node (from the Tree Viewer) with the Result Viewer. 

When a volume, file, folder, etc., is selected from the Tree Viewer, additional information about the selected item is displayed in the Result Viewer. For example, the Sample case's data source is selected, and now additional information is visible in the Results Viewer. 

![Autopsy - Table view 1](https://assets.tryhackme.com/additional/autopsy/autopsy-table-view.png)  

If a volume is selected, the Result Viewer's information will change to reflect the information in the local database for the selected volume. 

![Autopsy - Table view 2](https://assets.tryhackme.com/additional/autopsy/autopsy-table-view2.png)  

Notice that the Result Viewer pane has three tabs: **Table**, **Thumbnail**, and **Summary**. The above screenshots reflect the information displayed in the Table tab. The Thumbnail tab works best with image or video files. If the view of the above data is changed from Table to Thumbnail, not much information will be displayed. See below.

![Autopsy - Thumbnail view](https://assets.tryhackme.com/additional/autopsy/autopsy-thumbnail-view.png)  

Volume nodes can be expanded, and an analyst can navigate the volume's contents like a typical Windows system. 

![Autopsy - Volume](https://assets.tryhackme.com/additional/autopsy/autopsy-volume.png)  

In the **Views** tree node, files are categorised by File Types - **By Extension, By** **MIME Type**, **Deleted Files**, and **By** **File Size**.

![Autopsy - Views](https://assets.tryhackme.com/additional/autopsy/autopsy-views.png) 

**Tip**: When it comes to **File Types**, pay attention to this section. An adversary can rename a file with a misleading file extension. So the file will be 'miscategorised' **By** **Extension** but will be categorised appropriately by **MIME Type**. Expand **By Extension** and more children nodes appear, categorising files even further (see below).

![Autopsy - By extension](https://assets.tryhackme.com/additional/autopsy/autopsy-byextension.png)  

Refer to the Autopsy documentation on the **Result Viewer** for more information [here](http://sleuthkit.org/autopsy/docs/user-docs/4.12.0/result_viewer_page.html).   

**Contents Viewer**

From the Table tab in the Result Viewer, if you click any folder/file, additional information is displayed in the Contents Viewer pane.   

![Autopsy - Contents view](https://assets.tryhackme.com/additional/autopsy/autopsy-contents-view.png)

In the given image, three columns might not be quickly understood what they represent. 

- **S** = **Score**

The **Score** will show a red exclamation point for a folder/file marked/tagged as notable and a yellow triangle pointing downward for a folder/file marked/tagged as suspicious. These items can be marked/tagged by an Ingest Module or the analyst.

- **C** = **Comment**

If a yellow page is visible in the Comment column, it will indicate that there is a comment for the folder/file. 

- **O** = **Occurrence** 

In a nutshell, this column will indicate how many times this file/folder has been seen in past cases (this will require the [Central Repository](http://sleuthkit.org/autopsy/docs/user-docs/4.12.0/central_repo_page.html))

Refer to the Autopsy documentation on the Contents Viewer for more information [here](http://sleuthkit.org/autopsy/docs/user-docs/4.12.0/content_viewer_page.html).   

**Keyword Search**

At the top right, you will find **Keyword Lists** and **Keyword Search**. With **Keyword Search,** an analyst can perform an AD-HOC keyword search. 

![Autopsy - Keyword Search 1](https://assets.tryhackme.com/additional/autopsy/autopsy-keyword-search.png)  

In the image above, the analyst searches for the word 'secret.' Below are the search results.

![Autopsy - Keyword search 2](https://assets.tryhackme.com/additional/autopsy/autopsy-keyword-search2.png)  

Refer to the Autopsy [documentation](http://sleuthkit.org/autopsy/docs/user-docs/4.12.0/ad_hoc_keyword_search_page.html) for more information on performing keyword searches with either option. 

**Status Area**

Lastly, the **Status Area** is at the bottom right. When Ingest Modules run, a progress bar (along with the percentage completed) will be displayed in this area. More detailed information regarding the Ingest Modules is provided if you click on the bar.   

![Autopsy - Status bar](https://assets.tryhackme.com/additional/autopsy/autopsy-statusbar2.png)  

If the `X` (directly next to the progress bar) is clicked, a prompt will appear confirming if you wish to end/cancel the Ingest Modules. 

Refer to the Autopsy documentation on the UI overview [here](http://sleuthkit.org/autopsy/docs/user-docs/4.12.0/uilayout_page.html).


**The User Interface II**

Let's look at where we can find summarised info with ease. Summarised info can help analysts decide where to focus by evaluating available artefacts. It is suggested to view the summary of the data sources before starting an investigation. Therefore you can have a general idea about the system and artefacts.

**Data Sources Summary**

The **Data Sources Summary** provides summarised info in nine different categories. Note that this is an overview of the total findings. If you want to dive deep into the findings and look for a specific artefact, you need to analyse each module separately using the **"Result Viewer"** shown in the previous task. 

![Autopsy - Data sources summary](https://tryhackme-images.s3.amazonaws.com/user-uploads/6131132af49360005df01ae3/room-content/a8ab6999fabaf538c2e9eb3742b0ff29.png)  

Generate Report

You can create a report of your findings in multiple formats, enabling you to create data sheets for your investigation case. The report provides all information listed under the "Result Viewer" pane. Reports can help you to re-investigate findings after finishing the live investigation. **However, reports don't have additional search options, so you must manually find artefacts for the event of interest.**

**Tip:** The Autopsy tool can be heavy for systems with low resources. Therefore completing an investigation with Autopsy on low resources can be slow and painful. Especially browsing long results might end up with a system freeze. You can avoid that situation by using reports. You can use the tool for parsing the data and generating the report, then continue to analyse through the generated report without a need for Autopsy. Note that it is always easier to conduct and manage an investigation with the GUI.

You can use the **"Generate Report"** option to create reports. The steps are shown below.  
  

![Autopsy - Generate report](https://tryhackme-images.s3.amazonaws.com/user-uploads/6131132af49360005df01ae3/room-content/581fe3b1caa19ed94ad2564e3ecd8003.png)  

Once you choose your report format and scope, Autopsy will generate the report. You can click on the "HTML Report" section (shown above) to view the report on your browser. Reports contain all of the "Result Viewer" pane results on the left side.

![Autopsy - HTML report sample](https://tryhackme-images.s3.amazonaws.com/user-uploads/6131132af49360005df01ae3/room-content/68fc3dcf815f47183dd62c35438dc98c.png)

