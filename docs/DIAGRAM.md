# Diagram

## Figure 1.1 — System Overview

```mermaid
flowchart LR

    User([User])

    CLI["SentinelX CLI"]

    Target["Inspection Target"]

    Engine["SentinelX Engine"]

    Report["Inspection Report"]

    User --> CLI
    CLI --> Target
    Target --> Engine
    Engine --> Report
    Report --> User
```

## Figure 1.2 — High-Level Architecture
```mermaid
flowchart LR

    CLI["CLI"]

    subgraph Engine["SentinelX Engine"]

        Inspection["Inspection"]

        Analysis["Analysis"]

        Assessment["Assessment"]

        Presentation["Presentation"]

        Inspection --> Analysis
        Analysis --> Assessment
        Assessment --> Presentation

    end

    Report["Inspection Report"]

    CLI --> Inspection
    Presentation --> Report
```


## Figure 1.3 — Low-Level Architecture (Master)

```mermaid
flowchart TB

%% ===================================================================
%% INPUT
%% ===================================================================

InspectionTarget["Inspection Target"]

%% ===================================================================
%% ROUTING
%% ===================================================================

subgraph SG_Orchestration["Inspection Orchestration"]

InspectionOrchestrator["Inspection Orchestrator"]

MetadataInspection["Metadata Inspection"]

FileTypeDetection["File Type Detection"]

HashInspection["Hash Inspection"]

InspectorDispatch["Inspector Dispatch"]

InspectionOrchestrator --> MetadataInspection

MetadataInspection --> FileTypeDetection

FileTypeDetection --> HashInspection

HashInspection --> InspectorDispatch

end

InspectionTarget --> InspectionOrchestrator



%% ===================================================================
%% INSPECTION
%% ===================================================================

subgraph SG_Inspection["Inspection"]

    subgraph SG_PEInspection["PE Inspection"]

        PEInspector["PE Inspector"]

        PEHeaderInspection["PE Header Inspection"]

        PEMemoryInspection["PE Memory Inspection"]

        PEExecutionInspection["PE Execution Inspection"]

        PESecurityInspection["PE Security Inspection"]

        PESectionInspection["PE Section Inspection"]

        PEDirectoryInspection["PE Directory Inspection"]

        PEInspector --> PEHeaderInspection

        PEHeaderInspection --> PEMemoryInspection

        PEMemoryInspection --> PEExecutionInspection

        PEExecutionInspection --> PESecurityInspection

        PESecurityInspection --> PESectionInspection

        PESectionInspection --> PEDirectoryInspection

    end

    subgraph SG_DocumentInspection["Document Inspection"]

        DocumentInspector["Document Inspector"]

    end

    subgraph SG_ArchiveInspection["Archive Inspection"]

        ArchiveInspector["Archive Inspector"]

    end

    subgraph SG_ImageInspection["Image Inspection"]

        ImageInspector["Image Inspector"]

    end

end

InspectorDispatch --> PEInspector
InspectorDispatch --> DocumentInspector
InspectorDispatch --> ArchiveInspector
InspectorDispatch --> ImageInspector


%% ===================================================================
%% OBSERVATION
%% ===================================================================

subgraph SG_Observation["Observation"]

    Observation["Observation"]

    ObservationStore[("Observation Store")]

    Observation --> ObservationStore

end


DocumentInspector --> Observation
ArchiveInspector --> Observation
ImageInspector --> Observation
PEDirectoryInspection --> Observation

%% ===================================================================
%% ANALYSIS
%% ===================================================================

subgraph SG_Analysis["Analysis"]

    AnalysisPipeline["Analysis Pipeline"]

    AnalysisContext["Analysis Context"]

    Analyzer["Analyzer"]

end

ObservationStore --> AnalysisPipeline

AnalysisPipeline --> AnalysisContext

AnalysisContext --> Analyzer

%% ===================================================================
%% FINDING
%% ===================================================================

subgraph SG_Finding["Finding"]

    Finding["Finding"]

    FindingStore[("Finding Store")]

    Finding --> FindingStore

end

Analyzer --> Finding

%% ===================================================================
%% ASSESSMENT
%% ===================================================================

subgraph SG_Assessment["Assessment"]

    AssessmentPipeline["Assessment Pipeline"]

    AssessmentContext["Assessment Context"]

    Assessor["Assessor"]

    AssessmentPipeline --> AssessmentContext

    AssessmentContext --> Assessor

end

FindingStore --> AssessmentPipeline

%% ===================================================================
%% ASSESSMENT RESULT
%% ===================================================================

subgraph SG_AssessmentResult["Assessment Result"]

    Assessment["Assessment"]

    AssessmentStore[("Assessment Store")]

    Assessment --> AssessmentStore

end

Assessor --> Assessment

%% ===================================================================
%% PRESENTATION
%% ===================================================================

subgraph SG_Presentation["Presentation"]

    PresentationPipeline["Presentation Pipeline"]

    PresentationContext["Presentation Context"]

    Presenter["Presenter"]

    PresentationPipeline --> PresentationContext

    PresentationContext --> Presenter

end

AssessmentStore --> PresentationPipeline

%% ===================================================================
%% REPORT
%% ===================================================================

subgraph SG_Report["Report"]

    InspectionReport["Inspection Report"]

end

Presenter --> InspectionReport
```



## Figure 2.1 — Inspection Architecture

```mermaid
flowchart LR

    A[Inspection]
        --> B[Inspection Orchestrator]

    B --> C[General Inspection]

    C --> D[Inspector Dispatch]

    D --> E[Format Inspector]

    E --> F[Observation]

    E --> G[Discovered Target]
```


## Figure 2.2 — Inspection Routing

```mermaid
flowchart LR

    A[Inspection Target]

        --> B[Target Resolution]

    B --> C[General Inspection]

    C --> D[Inspector Dispatch]

    D --> E[Format Inspector]
```

## Figure 2.3 — Inspection Target

```mermaid
flowchart LR

    A[Root Target]

    A --> B[Discovered Target]

    A --> C[Discovered Target]

    B --> D[Discovered Target]
```

## Figure 2.4 — Inspector Contract

```mermaid
flowchart TB

    A[Inspector]

    A --> B[Observation]

    A --> C[Discovered Target]
```

## Figure 2.5 — PE Inspection

```mermaid
flowchart TB

    A[PE Inspector]

    A --> B[Header Inspection]

    A --> C[Section Inspection]

    A --> D[Directory Inspection]

    A --> E[Memory Inspection]

    A --> F[Security Inspection]

    A --> G[Execution Inspection]
```