// ===== script.js =====

// --- Global Variables & Map Initialization ---

const API_BASE_URL = ""; // Use relative path if connecting Pages->Worker


let map = L.map('map').setView([42.3, -83], 9);
L.tileLayer('https://{s}.basemaps.cartocdn.com/light_all/{z}/{x}/{y}{r}.png', {
  attribution: '© CARTO',
  subdomains: 'abcd',
  maxZoom: 19
}).addTo(map);
L.control.scale({ position: 'bottomleft' }).addTo(map);

let geojsonLayer; // Holds the currently displayed choropleth layer
let legend = L.control({ position: 'bottomright' });
let data; // Holds the master GeoJSON data (updated after index generation)
let currentSelected = new Set(); // Holds variables selected for index creation
let activeField = ''; // The field ID currently displayed on the main map
let activityLayer = null; // Holds the generated activity index GeoJSON layer object
let residentialLayer = null; // Holds the generated residential index GeoJSON layer object
let activityFieldName = ''; // Holds the name (field ID) of the generated activity index
let residentialFieldName = ''; // Holds the name (field ID) of the generated residential index
let raceLegend = null; // Variable to hold the race legend control
let raceBorderLayer = null; // Layer specifically for race borders
let legendLeft = null;
let legendRight = null;
let generatedIndexMetadata = {
    residential: { name: null, description: null, variables: [], fieldName: null, stats: null },
    activity: { name: null, description: null, variables: [], fieldName: null, stats: null }
};


// --- Data Structures ---

// Mapping for County FIPS codes to names
const countyMapping = {
 '93': 'Livingston',
 '99': 'Macomb',
 '115': 'Monroe',
 '125': 'Oakland',
 '147': 'St. Clair',
 '161': 'Washtenaw',
 '163': 'Wayne'
};


// Structure defining variables for the main display dropdown
const displayableVariables = {
  "Social & Demographic": [
    // Corrected: Use actual column name 'no_high_school_ed_o' if that's the column
    // Or keep 'no_high_school_rate_o' if that exists and is preferred
    { id: "no_high_school_rate_o", name: "% population without high school education" }, // Verify this column name exists
    { id: "no_car_rate_o", name: "% household owns no automobiles" },
    { id: "total_no_work_rate_o", name: "% unemployed population" },
    { id: "poverty_rate_o", name: "% of the population in poverty" },
    { id: "renter_rate_o", name: "% household is renter occupied" },
    { id: "total_no_ins_rate_o", name: "% of the uninsured population" },
  ],
  "Built Environment": [
     { id: "sdwalk_length_m_o", name: "Sidewalk length (total)" },
     { id: "bik_length_m_o", name: "Bikeway length (total)" },
     { id: "park_area_o", name: "Public open spaces (total)" },
     { id: "sidewalk_per_cap_o", name: "Sidewalk length per capita" },
     { id: "park_per_cap_o", name: "Public open spaces per capita" },
     { id: "bike_per_cap_o", name: "Bikeway length per capita" },
     { id: "healthy_retailer_o", name: "# of healthy food retailers" },
     { id: "pharma_o", name: "# of pharmacy stores" },
     { id: "clinic_o", name: "# of clinics" },
     { id: "healthy_ret_cap_o", name: "# of healthy food retailers per capita" },
     { id: "pharma_cap_o", name: "# of pharmacy stores per capita" },
     { id: "clinic_cap_o", name: "# of clinics per capita" },
     // --- Corrected IDs ---
     { id: "unhealthy_ret_cap_o", name: "# of less healthy food retailers per capita"},
     { id: "liq_tab_cap_o", name: "# tobacco and liquor retail stores per capita"},
     // --- Added ---
     { id: "food_retailer_cap_o", name: "# of food retailers per capita"}, // Added from geojson list
  ],
   "Environmental Exposure": [
     // --- Corrected IDs to use _zscore_o as those seem available ---
     // --- Adjust friendly names if needed ---
     { id: "PRE1960PCT_o", name: "% pre-1960 housing" },
     { id: "OZONE_o", name: "Ozone level in air" },
     { id: "PM25_o", name: "Particulate matter 2.5 (PM2.5)" },
     { id: "PNPL_o", name: "Proximity to NPL sites" },
     { id: "PRMP_o", name: "Proximity to RMP facilities" },
     { id: "PTSDF_o", name: "Proximity to TSDF facilities" },
     { id: "DSLPM_o", name: "Diesel PM level"}, // Added from geojson list
   ],
    "Health Outcomes": [
    // --- These match your sample/list ---
    { id: 'Obesity', name: 'Obesity Rate (%)' }, // Added units for clarity
    { id: 'Diabetes', name: 'Diabetes Rate (%)' },
    { id: 'High Blood Pressure', name: 'High Blood Pressure Rate (%)' },
    { id: 'Coronary Heart Disease', name: 'Coronary Heart Disease Rate (%)' },
    { id: 'High Cholesterol', name: 'High Cholesterol Rate (%)' },
    { id: 'Depression', name: 'Depression Rate (%)' },
    { id: 'Stroke', name: 'Stroke Rate (%)' },
    { id: 'Annual Checkup', name: 'Annual Checkup Rate (%)' },
    { id: 'Physical Inactivity', name: 'Physical Inactivity Rate (%)' }
  ],
  "Pre-defined Indices": [
    { id: "ndi_o", name: "Neighborhood Disadvantage Index (NDI)*100" },
    { id: "uei_o", name: "Unhealthy Exposure Index (UEI)*100" },
    { id: "hoi_o", name: "Health Opportunity Index (HOI)*100" },
    { id: "andi_final", name: "Activity Space Neighborhood Disadvantage Index (ANDI)*100" },
    { id: "auei_final", name: "Activity Space Unhealthy Exposure Index (AUEI)*100" },
    { id: "ahoi_final", name: "Activity Space Health Opportunity Index (AHOI)*100" },

  ]
};

const raceFormattingMap = {
    'white': 'White',
    'black': 'Black/African American',
    'hisp': 'Hispanic/Latino',
    'asian': 'Asian',
    'other': 'Other/Mixed Race'
    // Add other mappings if your 'race' column has different values
};


const selectedVariablesDiv = document.getElementById('selected-variables');
const fieldSelect = document.getElementById('field-select');



// --- Helper function to create a legend control ---
function createLegendControl(fieldName, breaks) {
    const legendControl = L.control({ position: 'bottomright' });
    legendControl.onAdd = function (map) {
        const div = L.DomUtil.create('div', 'info legend');
        let friendlyLegendName = fieldName; // Get friendly name
         // Add logic here to lookup friendly name if needed, similar to generateLayerFromField
         if (fieldName === activityFieldName) friendlyLegendName = `Activity Space: ${fieldName}`;
         if (fieldName === residentialFieldName) friendlyLegendName = `Residential: ${fieldName}`;

        div.innerHTML += `<strong>${friendlyLegendName}</strong>`;
        if (breaks && breaks.length > 1) {
             div.innerHTML += `<i style="background:${getColor(breaks[0], breaks)}"></i> <span>≤ ${breaks[1].toFixed(1)}</span><br>`;
             for (let i = 1; i < breaks.length - 1; i++) {
               div.innerHTML += `<i style="background:${getColor(breaks[i] + 0.01, breaks)}"></i> <span>${breaks[i].toFixed(1)}–${breaks[i + 1].toFixed(1)}</span><br>`;
             }
        } else {
             div.innerHTML += '<br><span>No data breaks</span>';
        }
        div.innerHTML += '<i style="background:#ccc"></i> <span>No data</span>';
        return div;
    };
    return legendControl;
}

// --- Helper function to remove comparison legends ---
function removeComparisonLegends() {
    if (legendLeft && mapLeft && typeof mapLeft.removeControl === 'function') {
        try { mapLeft.removeControl(legendLeft); } catch(e){}
    }
    if (legendRight && mapRight && typeof mapRight.removeControl === 'function') {
         try { mapRight.removeControl(legendRight); } catch(e){}
    }
    legendLeft = null;
    legendRight = null;
}

// (Handles base variables, indices, etc.)
function getFriendlyFieldName(fieldId) {
    if (!fieldId) return "Unknown Field";

    // 1. Check if it's a known generated index
    if (fieldId === activityFieldName) return `Activity Index: ${fieldId}`;
    if (fieldId === residentialFieldName) return `Residential Index: ${fieldId}`;

    // 2. Check if it's in the displayableVariables list
    for (const group in displayableVariables) {
        const variable = displayableVariables[group].find(v => v.id === fieldId);
        if (variable) {
            return variable.name; // Return the full name from the list
        }
    }

    // 3. Fallback: Clean up the field ID itself
    return fieldId.replace(/_/g, ' ').replace(/ \bo\b/g, '').replace(/ \bRES\b/g, ' (Residential)').replace(/ \bACT\b/g, ' (Activity)'); // Basic cleanup
}


// Helper function to format race names
function formatRaceName(rawRaceValue) {
    const lowerRace = (rawRaceValue || 'other').toLowerCase();
    return raceFormattingMap[lowerRace] || 'Unknown'; // Return formatted name or 'Unknown'
}

// --- Helper function to check if 'map' is a valid Leaflet map ---
function isValidMap(mapInstance) {
    // Check if it exists, is an object, and has a known Leaflet method (like 'addLayer')
    return mapInstance && typeof mapInstance === 'object' && typeof mapInstance.addLayer === 'function';
}

// --- Add Helper function to remove border layer ---
function removeRaceBorderLayer() {
    // Check if the global 'map' variable is valid AND if raceBorderLayer exists
    if (isValidMap(map) && raceBorderLayer) {
        // Use map.removeLayer - Leaflet handles the check internally if the layer is on the map
        try {
            map.removeLayer(raceBorderLayer);
            console.log("Removed existing race border layer.");
        } catch (e) {
            console.error("Error removing race border layer:", e);
            // Don't prevent rest of execution, just log the error
        }
    } else if (!isValidMap(map)) {
         console.warn("removeRaceBorderLayer called, but 'map' is not a valid Leaflet map object.");
    }
    raceBorderLayer = null; // Always reset the variable
}

// --- add RaceLegend ---
function addRaceLegend(selectedRaces) {
    // Remove existing race legend if it exists
    removeRaceLegend();

    // --- Check map validity BEFORE creating/adding control ---
    if (!isValidMap(map)) {
        console.error("Cannot add race legend: Leaflet map object is invalid.");
        return; // Don't proceed if map isn't valid
    }
    // --- End check ---

    raceLegend = L.control({ position: 'topright' }); // Or another position

    raceLegend.onAdd = function (map) {
        const div = L.DomUtil.create('div', 'info legend race-legend');
        div.innerHTML += '<strong>Selected Races</strong>';

        selectedRaces.forEach(race => {
            const color = getRaceColor(race);
            const formattedName = formatRaceName(race); // Use the formatting function from step 5
            div.innerHTML +=
                `<div><i style="background: transparent; border: 2.5px solid ${color};"></i> ${formattedName}</div>`;
        });
        // Optionally add non-selected style
         div.innerHTML += `<div><i style="background: transparent; border: 0.5px dashed #aaa;"></i> Other Tracts</div>`;

        return div;
    };

    raceLegend.addTo(map);
    console.log("Added race legend control.");
}

function removeRaceLegend() {
    // Check if the global 'map' variable is valid AND if raceLegend exists
    if (isValidMap(map) && raceLegend) {
        // Use map.removeControl directly - Leaflet handles the check internally
        // No need for map.hasControl which might not always be present depending on Leaflet version/plugins
        try {
             map.removeControl(raceLegend);
             console.log("Removed existing race legend control.");
        } catch (e) {
             console.error("Error removing race legend control:", e);
             // Don't prevent rest of execution, just log the error
        }
    } else if (!isValidMap(map)) {
         console.warn("removeRaceLegend called, but 'map' is not a valid Leaflet map object.");
    }
    raceLegend = null; // Always reset the variable
}

// --- Call removeRaceLegend when analysis should be cleared ---
// For example, when changing the main variable dropdown:
document.getElementById('field-select').addEventListener('change', e => {
    removeRaceLegend(); 
    removeRaceBorderLayer(); 
    const selectedField = e.target.value;
    // ... rest of existing listener ...
});

// Also potentially call removeRaceLegend when generating a new index or resetting selection
// --- Choropleth Map Generation ---

// Color scale function using Jenks breaks
function getColor(value, breaks) {
  if (value == null || isNaN(value)) return '#ccc'; // Color for no data
  // Using a diverging color scheme example (adjust colors as needed)
  return value > breaks[4] ? '#8c510a' : // Darkest Brown
         value > breaks[3] ? '#bf812d' :
         value > breaks[2] ? '#f6e8c3' : // Lightest Yellow (Midpoint)
         value > breaks[1] ? '#80cdc1' :
                             '#01665e'; // Darkest Teal
}

// --- Function to generate and download Raw Index Data CSV ---
function downloadIndexDataCSV(indexType) { // indexType = 'residential' or 'activity'
    const metadata = generatedIndexMetadata[indexType];
    if (!metadata || !metadata.fieldName || !data || !data.features) {
        alert(`Cannot download data. ${indexType.charAt(0).toUpperCase() + indexType.slice(1)} Index has not been generated or data is missing.`);
        return;
    }

    console.log(`Preparing download for ${indexType} index: ${metadata.fieldName}`);

    let csvContent = generateMetadataHeader();

    // Add Index Specific Info
    csvContent += `# Index Details:\n`;
    csvContent += `# Name: ${metadata.name || '(Not Set)'}\n`;
    csvContent += `# Field ID: ${metadata.fieldName}\n`;
    csvContent += `# Description: ${metadata.description || '(Not Set)'}\n`;
    csvContent += `# Variables Used: ${metadata.variables.join(', ')}\n`;
    csvContent += `# --------------------------------------------------\n\n`;

    // --- Prepare CSV Header ---
    const headers = [
        'Origin_tract',
        'COUNTYFP', // Use the actual property name from GeoJSON
        'CountyName',
        'population_x_o', // Use actual property name
        'race', // Use actual property name
        // ...metadata.variables, // Input variables used
        metadata.fieldName // The index score itself
    ];
    // Function to safely quote CSV fields containing commas or quotes
    const escapeCSV = (field) => {
        const strField = String(field === null || field === undefined ? '' : field);
        if (strField.includes(',') || strField.includes('"') || strField.includes('\n')) {
            return `"${strField.replace(/"/g, '""')}"`; // Quote and double-up existing quotes
        }
        return strField;
    };

    csvContent += headers.map(escapeCSV).join(',') + '\n';

    // --- Add Data Rows ---
    data.features.forEach(feature => {
        const props = feature.properties;
        const row = [];
        row.push(props['Origin_tract'] || '');
        const countyFips = props['COUNTYFP'];
        row.push(countyFips || '');
        row.push(countyFips ? (countyMapping[countyFips] || '') : ''); // Add County Name
        row.push(props['population_x_o'] || ''); // Verify this property name
        row.push(props['race'] || ''); // Verify this property name

        // // Add values for input variables
        // metadata.variables.forEach(varId => {
        //     row.push(props[varId] !== undefined && props[varId] !== null ? props[varId] : '');
        // });
        // Add the index score
        row.push(props[metadata.fieldName] !== undefined && props[metadata.fieldName] !== null ? props[metadata.fieldName] : '');

        csvContent += row.map(escapeCSV).join(',') + '\n';
    });

    // --- Trigger Download ---
    const safeFieldName = indexFieldName.replace(/[^a-zA-Z0-9_-]/g, '_').replace(/_+/g, '_');
    downloadData(csvContent, `index_summary_${safeFieldName}.csv`, 'text/csv;charset=utf-8;');
}

// --- Function to generate and download Race Analysis Table CSV ---
function downloadRaceAnalysisCSV() {
    // Determine which index was last analyzed (or default)
    // This relies on generatedIndexMetadata storing the latest stats
    let activeAnalysis = null;
    if (generatedIndexMetadata.residential.stats) activeAnalysis = generatedIndexMetadata.residential;
    if (generatedIndexMetadata.activity.stats) activeAnalysis = generatedIndexMetadata.activity; // Activity takes precedence if both exist? Choose one.

    if (!activeAnalysis || !activeAnalysis.stats) {
        alert("No race analysis data available to download. Please run an analysis first.");
        return;
    }

    const stats = activeAnalysis.stats;
    const indexField = activeAnalysis.fieldName;

    console.log(`Preparing download for race analysis table: ${indexField}`);

    let csvContent = generateMetadataHeader();

    // Add Analysis Specific Info
    csvContent += `# Race Analysis Details:\n`;
    csvContent += `# Index Analyzed: ${indexField}\n`;
    csvContent += `# Index Name: ${activeAnalysis.name || '(Not Set)'}\n`;
    csvContent += `# --------------------------------------------------\n\n`;

    // --- Prepare CSV Header ---
    const headers = ['Group', 'Tract Count', 'Median', 'IQR', 'Mean'];
     const escapeCSV = (field) => { /* ... same escape function as above ... */
         const strField = String(field === null || field === undefined ? '' : field);
         if (strField.includes(',') || strField.includes('"') || strField.includes('\n')) {
             return `"${strField.replace(/"/g, '""')}"`;
         }
         return strField;
     };
    csvContent += headers.map(escapeCSV).join(',') + '\n';

    // --- Add Data Rows ---
    const groups = Object.keys(stats).filter(g => g !== 'all_tracts');
    if (stats['all_tracts']) groups.push('all_tracts'); // Add 'all_tracts' to the end

    groups.forEach(group => {
        const s = stats[group];
        const row = [
            formatRaceName(group) || group.replace('_', ' '), // Use formatted name
            s.count,
            s.median,
            s.iqr,
            s.mean
        ];
        csvContent += row.map(escapeCSV).join(',') + '\n';
    });

    // --- Trigger Download ---
    downloadData(csvContent, `race_analysis_${indexField}.csv`, 'text/csv;charset=utf-8;');
}

// ==========================================================
// HELPER FUNCTION TO MANAGE BUTTON STATES
// ==========================================================
// ==========================================================
// HELPER FUNCTION TO MANAGE BUTTON STATES (REVISED V2)
// ==========================================================
function setIndexActiveState(indexType, isActive) {
    // indexType should be 'residential' or 'activity'
    console.log(`Setting index state for '${indexType}' to active=${isActive}`); // Add logging

    const generateButtonId = (indexType === 'activity') ? 'generate-index' : 'generate-residential';
    const generateButton = document.getElementById(generateButtonId);
    const tableButton = document.getElementById(`show-table-${indexType}`);
    const histogramButton = document.getElementById(`show-histogram-${indexType}`);
    const analyzeButton = document.getElementById(`analyze-${indexType}`);
    const downloadDataButton = document.getElementById(`download-${indexType}-data`);
    const downloadMapButton = document.getElementById('download-map-image');

    // --- Check if elements exist ---
    // (Keep the checks from previous version)
    let elementsFound = true;
    if (!generateButton) { console.error(`setIndexActiveState: Missing button ID '${generateButtonId}'`); elementsFound = false; }
    if (!tableButton) { console.error(`setIndexActiveState: Missing button ID 'show-table-${indexType}'`); elementsFound = false; }
    if (!histogramButton) { console.error(`setIndexActiveState: Missing button ID 'show-histogram-${indexType}'`); elementsFound = false; }
    if (!analyzeButton) { console.error(`setIndexActiveState: Missing button ID 'analyze-${indexType}'`); elementsFound = false; }
    if (!downloadDataButton) { console.error(`setIndexActiveState: Missing button ID 'download-${indexType}-data'`); elementsFound = false; }
    // Map download button is optional
    if (!downloadMapButton) { console.warn(`setIndexActiveState: Map download button 'download-map-image' not found.`);}

    if (!elementsFound) {
        console.error(`Cannot fully set index state for '${indexType}' due to missing essential elements.`);
        return;
    }
    // --- End Check ---

    // --- Update State ---
    if (isActive) {
        // --- Activate State ---
        generateButton.classList.add('activated'); // Visual activation

        // Enable action buttons - these should ALWAYS be enabled if isActive is true
        // because it means the index generation was successful.
        tableButton.disabled = false;
        histogramButton.disabled = false;
        analyzeButton.disabled = false;
        downloadDataButton.disabled = false; // Directly enable data download

        // Enable map download button as well when an index is active
        if (downloadMapButton) downloadMapButton.disabled = false;

        // Add visual class for enabled icon buttons (if using CSS class)
        tableButton.classList.add('index-action-enabled');
        histogramButton.classList.add('index-action-enabled');
        console.log(` -> Enabled buttons for ${indexType}: Table, Hist, Analyze, Download Data`);


    } else {
        // --- Deactivate State ---
        generateButton.classList.remove('activated'); // Visual deactivation

        // Disable action buttons
        tableButton.disabled = true;
        histogramButton.disabled = true;
        analyzeButton.disabled = true;
        downloadDataButton.disabled = true; // Always disable data download when inactive

        // Disable map download ONLY if the OTHER index type is ALSO inactive
        const otherIndexType = indexType === 'activity' ? 'residential' : 'activity';
        const isOtherTypeActive = generatedIndexMetadata[otherIndexType] && generatedIndexMetadata[otherIndexType].fieldName;

        if (downloadMapButton && !isOtherTypeActive) {
            // Only disable map download if no base variable is active either
             if (!activeField || (activeField !== generatedIndexMetadata.activity?.fieldName && activeField !== generatedIndexMetadata.residential?.fieldName)) {
                 // If activeField is empty OR it's not one of the generated indices, disable map dl
                 // downloadMapButton.disabled = true; // Re-evaluate this - maybe keep enabled if ANY layer is shown? Let's keep it enabled if a base var is shown.
             } else {
                  // Keep enabled if activeField is one of the indices (which should not happen if we call this with isActive=false)
             }
        } else if (downloadMapButton && isOtherTypeActive){
             // Keep enabled if other index is active
             downloadMapButton.disabled = false;
        }


        // Remove visual class for enabled icon buttons
        tableButton.classList.remove('index-action-enabled');
        histogramButton.classList.remove('index-action-enabled');
        console.log(` -> Disabled buttons for ${indexType}: Table, Hist, Analyze, Download Data`);
    }
}

// Generates and displays (or just returns) a choropleth layer for a given field
async function generateLayerFromField(field, returnOnly = false) {
    // **** DECLARE mapDownloadButton HERE ****
    const mapDownloadButton = document.getElementById('download-map-image');
    // **** END DECLARATION ****

    if (!data || !data.features || data.features.length === 0) {
        console.error("Cannot generate layer: GeoJSON data is not loaded or empty.");
        // Disable map download if data is missing
        if (mapDownloadButton) mapDownloadButton.disabled = true;
        return null;
    }

    // Extract valid numeric values for the selected field
    const values = data.features
        .map(f => parseFloat(f.properties[field]))
        .filter(v => v !== null && v !== undefined && !isNaN(v));

    if (!values.length) {
        console.warn(`No valid numeric data found for field: ${field}`);
        if (!returnOnly) {
            if (geojsonLayer && map.hasLayer(geojsonLayer)) geojsonLayer.remove(); // Use hasLayer for safety
             geojsonLayer = L.geoJson(data, {
                 style: { fillColor: '#ccc', weight: 1, color: 'white', fillOpacity: 0.7 },
                 onEachFeature: (feature, layer) => {
                     const props = feature.properties;
                     const tractId = props['Origin_tract'] || 'N/A';
                     const population = props['population_x_o'] !== undefined ? props['population_x_o'].toLocaleString() : 'N/A';
                     const countyFips = props['COUNTYFP'];
                     const countyName = countyFips ? (countyMapping[countyFips] || `Unknown (${countyFips})`) : 'N/A';
                     layer.bindTooltip(`<strong>Tract:</strong> ${tractId}<br><strong>County:</strong> ${countyName}<br><strong>Population:</strong> ${population}<br><strong>${getFriendlyFieldName(field)}:</strong> No Data`); // Use friendly name
                 }
             }).addTo(map);
             if (legend) map.removeControl(legend);
             activeField = field;
             document.getElementById('index-info').innerHTML = `Displaying: <strong>${getFriendlyFieldName(field)}</strong> (No numeric data found)`; // Use friendly name
         }
         // Disable map download on no data
         if (mapDownloadButton) mapDownloadButton.disabled = true; // <-- Use the declared variable
         return null;
    }

    // Calculate Jenks breaks using simple-statistics
     const ss = await import('https://cdn.skypack.dev/simple-statistics');
     // Add try-catch for Jenks calculation which can fail with insufficient distinct values
     let breaks;
     try {
         breaks = ss.jenks(values, 5); // 5 breaks = 6 classes
     } catch (jenksError) {
         console.error(`Jenks calculation failed for field ${field}:`, jenksError);
         // Handle gracefully - maybe show 'No data' or a simpler classification
         if (!returnOnly) {
             if (geojsonLayer && map.hasLayer(geojsonLayer)) geojsonLayer.remove();
             geojsonLayer = L.geoJson(data, { style: { fillColor: '#ccc', weight: 1, color: 'white', fillOpacity: 0.7 }, onEachFeature: (feature, layer) => {/* ... no data tooltip ... */} }).addTo(map);
             if (legend) map.removeControl(legend); 
             document.getElementById('index-info').innerHTML = `Displaying: <strong>${getFriendlyFieldName(field)}</strong> (Error classifying data)`;
         }
         if (mapDownloadButton) mapDownloadButton.disabled = true;
         return null; // Stop processing this layer
     }


    // Create the GeoJSON layer with styling and popups
    const layer = L.geoJson(data, {
        style: feature => ({
            fillColor: getColor(parseFloat(feature.properties[field]), breaks),
            weight: 1,
            color: 'white',
            fillOpacity: 0.7
        }),
        onEachFeature: (feature, layer) => {
            const props = feature.properties;
            const tractId = props['Origin_tract'] || 'N/A';
            const valueRaw = props[field];
            const valueFormatted = (valueRaw === null || valueRaw === undefined || isNaN(parseFloat(valueRaw)))
                                    ? 'N/A'
                                    : parseFloat(valueRaw).toFixed(2);
            const populationRaw = props['population_x_o'];
            const population = (populationRaw !== null && populationRaw !== undefined)
                                 ? parseFloat(populationRaw).toLocaleString() // Ensure it's parsed if needed before formatting
                                 : 'N/A';
            const countyFips = props['COUNTYFP'];
            const countyName = countyFips ? (countyMapping[countyFips] || `Unknown (${countyFips})`) : 'N/A';
            const rawRace = props['race'];
            const formattedRace = formatRaceName(rawRace);
            const friendlyFieldName = getFriendlyFieldName(field); // Use helper

            let tooltipContent = `<strong>Tract:</strong> ${tractId}<br>`;
            tooltipContent += `<strong>County:</strong> ${countyName}<br>`;
            if (props.hasOwnProperty('race')) {
                tooltipContent += `<strong>Dominant Race Group:</strong> ${formattedRace}<br>`;
            }
            tooltipContent += `<strong>Population:</strong> ${population}<br>`;
            tooltipContent += `<strong>${friendlyFieldName}:</strong> ${valueFormatted}`;
            layer.bindTooltip(tooltipContent);
        }
    });

    // If only returning the layer object (e.g., for comparison maps)
    if (returnOnly) return layer;

    // --- Update the main map display ---
    if (geojsonLayer && map.hasLayer(geojsonLayer)) geojsonLayer.remove(); // Use hasLayer check
    geojsonLayer = layer.addTo(map);
    // map.fitBounds(layer.getBounds()); // Optionally zoom

    // --- Update Legend ---
    if (legend) map.removeControl(legend);
    legend.onAdd = function () { // Define legend content dynamically
        const div = L.DomUtil.create('div', 'info legend');
        const friendlyLegendName = getFriendlyFieldName(field); // Use helper
        div.innerHTML += `<strong>${friendlyLegendName}</strong><br>`;
        if (breaks && breaks.length > 1) { // Check breaks validity
            div.innerHTML += `<i style="background:${getColor(breaks[0], breaks)}"></i> ≤ ${breaks[1].toFixed(1)}<br>`;
            for (let i = 1; i < breaks.length - 1; i++) {
                div.innerHTML += `<i style="background:${getColor(breaks[i] + 0.01, breaks)}"></i> ${breaks[i].toFixed(1)}–${breaks[i + 1].toFixed(1)}<br>`;
            }
        } else {
             div.innerHTML += '<span>Data classification error</span><br>';
        }
        div.innerHTML += '<i style="background:#ccc"></i> No data';
        return div;
    };
    legend.addTo(map);

    activeField = field; // Update the currently active field tracker

    // --- ENABLE map download button ---
    if (mapDownloadButton) mapDownloadButton.disabled = false; // <-- Use the declared variable

    return layer; // Return the added layer
}


function makeDraggable(element, handle) {
    let pos1 = 0, pos2 = 0, pos3 = 0, pos4 = 0;

    // If handle is specified, bind to handle, otherwise bind to element itself
    const dragHandle = handle || element;

    dragHandle.onmousedown = dragMouseDown;

    function dragMouseDown(e) {
        e = e || window.event;
        e.preventDefault(); // Prevent default behavior (e.g., text selection)
        // get the mouse cursor position at startup:
        pos3 = e.clientX;
        pos4 = e.clientY;
        document.onmouseup = closeDragElement;
        // call a function whenever the cursor moves:
        document.onmousemove = elementDrag;
        dragHandle.style.cursor = 'grabbing'; // Change cursor while dragging
    }

    function elementDrag(e) {
        e = e || window.event;
        e.preventDefault();
        // calculate the new cursor position:
        pos1 = pos3 - e.clientX;
        pos2 = pos4 - e.clientY;
        pos3 = e.clientX;
        pos4 = e.clientY;
        // set the element's new position:
        // Ensure element stays within viewport boundaries (optional but recommended)
        const newTop = Math.max(0, Math.min(window.innerHeight - element.offsetHeight, element.offsetTop - pos2));
        const newLeft = Math.max(0, Math.min(window.innerWidth - element.offsetWidth, element.offsetLeft - pos1));

        element.style.top = newTop + "px";
        element.style.left = newLeft + "px";
    }

    function closeDragElement() {
        // stop moving when mouse button is released:
        document.onmouseup = null;
        document.onmousemove = null;
        dragHandle.style.cursor = 'move'; // Restore cursor
    }
}

// --- Initial Data Loading & UI Setup ---

document.addEventListener('DOMContentLoaded', () => {
  fetch(`${API_BASE_URL}/api/geojson`) 
    .then(res => {
        if (!res.ok) {
            throw new Error(`HTTP error! status: ${res.status}`);
        }
        return res.json();
     })
    .then(json => {
      if (json.error) { // Handle potential errors returned in JSON body
          throw new Error(`Server error: ${json.error}`);
      }
      if (!json || !json.features || json.features.length === 0) {
          throw new Error("Received empty or invalid GeoJSON data.");
      }

      data = json; // Store the initial data

      // Populate the main variable display dropdown
      populateDisplayVariableDropdown();

      // Set initial map view (e.g., NDI) and select it in the dropdown
      const initialField = 'ndi_o'; // Or choose another default
      const fieldSelector = document.getElementById('field-select');
      if (data.features[0].properties.hasOwnProperty(initialField)) {
          generateLayerFromField(initialField);
          fieldSelector.value = initialField; // Set dropdown selection
          updateInfoPanelForVariable(initialField);
      } else {
          console.error(`Initial field '${initialField}' not found in data.`);
          // Display the first available field from the dropdown if possible
          if (fieldSelector.options.length > 1) {
               fieldSelector.selectedIndex = 1; // Select the first actual variable
               generateLayerFromField(fieldSelector.value);
               updateInfoPanelForVariable(fieldSelector.value);
          } else {
              document.getElementById('index-info').innerHTML = 'No displayable variables found in data.';
          }
      }

      // Load variables for the index creation section
      loadIndexCreationVariables();

    })
    .catch(err => {
      console.error('Failed to load initial GeoJSON or setup:', err);
      alert(`Could not load the map data or initialize the application. Please check the console for details. Error: ${err.message}`);
      document.getElementById('index-info').innerHTML = 'Error loading map data.';
    });

    // Set copyright year in main app sidebar
    const mainCopyrightYearSpan = document.getElementById('copyright-year-main');
    if (mainCopyrightYearSpan) {
         mainCopyrightYearSpan.textContent = new Date().getFullYear();
    }

    // Disable analysis buttons initially
    document.getElementById('analyze-activity').disabled = true;
    document.getElementById('analyze-residential').disabled = true;

    // Attach other event listeners
    attachEventListeners();
});

function populateDisplayVariableDropdown() {
    const fieldSelector = document.getElementById('field-select');
    fieldSelector.innerHTML = '<option value="">-- Select a Variable --</option>'; // Default option

    Object.entries(displayableVariables).forEach(([groupName, variables]) => {
        const optgroup = document.createElement('optgroup');
        optgroup.label = groupName;
        variables.forEach(variable => {
            // Check if the variable actually exists in the loaded data properties
            if (data.features.length > 0 && data.features[0].properties.hasOwnProperty(variable.id)) {
                 const opt = document.createElement('option');
                 opt.value = variable.id;
                 opt.textContent = variable.name; // Use friendly name
                 opt.title = variable.name; 
                 optgroup.appendChild(opt);
            } else {
                console.warn(`Variable "${variable.id}" (${variable.name}) not found in GeoJSON properties.`);
            }
        });
        if (optgroup.childElementCount > 0) { // Only add group if it has valid options
             fieldSelector.appendChild(optgroup);
        }
    });
}

function updateInfoPanelForVariable(selectedField) {
    let friendlyName = selectedField;
    for (const group in displayableVariables) {
        const variable = displayableVariables[group].find(v => v.id === selectedField);
        if (variable) {
            friendlyName = variable.name;
            break;
        }
    }
     document.getElementById('index-info').innerHTML = `Displaying: <strong>${friendlyName}</strong>`;
}


// --- Index Creation Logic ---

// Fetch variables available for index creation and populate dropdowns
function loadIndexCreationVariables() {
    fetch(`${API_BASE_URL}/api/get_index_fields`) // Uses relative path
     .then(res => res.json())
     .then(indexVariables => {
         setupIndexVariableDropdowns(indexVariables); // Call the updated function
     })
     .catch(err => console.error("Failed to load index fields:", err));
}

// Populate the multi-select dropdowns for index creation
function setupIndexVariableDropdowns(indexVariables) { // indexVariables comes from /get_index_fields
    const socialSelect = document.getElementById('social-vars-select');
    const envSelect = document.getElementById('env-vars-select');
    // Add more selects if you have more categories (e.g., envExposureSelect)
    if (socialSelect) socialSelect.innerHTML = ''; else console.error("Element with ID 'social-vars-select' not found!"); // Add checks
    if (envSelect) envSelect.innerHTML = ''; else console.error("Element with ID 'env-vars-select' not found!"); // Add checks

    indexVariables.forEach(variableId => { // variableId is the base name expected by backend
        const displayInfo = getDisplayInfoForBaseVar(variableId);

        const option = document.createElement('option');
        option.value = variableId; // Use the base ID for the value sent to backend
        option.textContent = displayInfo.name; // Use the friendly name for display
        option.title = displayInfo.name;
        // Assign to the correct dropdown based on category
        if (displayInfo.category === 'Social & Demographic') {
            socialSelect.appendChild(option);
        } else { // Put everything else in the Env/Built Env dropdown for now
            envSelect.appendChild(option);
        }
        // Add more else if blocks for other categories if needed
    });

    // // Attach event listeners 
    // socialSelect.addEventListener('change', handleMultiSelectChange);
    // envSelect.addEventListener('change', handleMultiSelectChange);
    // --- ATTACH NEW SINGLE-CLICK LISTENERS ---
    attachSingleClickMultiSelect(socialSelect);
    attachSingleClickMultiSelect(envSelect);
}

// Helper function to find display info (name, category) for a base variable ID
function getDisplayInfoForBaseVar(baseVarId) {
    for (const [groupName, variables] of Object.entries(displayableVariables)) {
        // Try matching directly or by removing common suffixes like _o, _zscore_o
        const potentialIds = [baseVarId, `${baseVarId}_o`, `${baseVarId}_zscore_o`];
        for (const potentialId of potentialIds) {
             const variableInfo = variables.find(v => v.id === potentialId);
             if (variableInfo) {
                 // Determine category based on groupName (adjust group names if needed)
                 let category = 'Environmental & Built Environment'; // Default
                 if (groupName === 'Social & Demographic') category = 'Social & Demographic';
                 // Add more categories if necessary (e.g., 'Environmental Exposure')

                 return { name: variableInfo.name.replace(' (z-score)', ''), category: category }; // Return base name and category
             }
        }
    }
    // Fallback if no match found
    return { name: baseVarId.replace(/_/g, ' '), category: 'Environmental & Built Environment' };
}

// Handle changes in the multi-select dropdowns
function handleMultiSelectChange() {
    currentSelected.clear(); // Reset the set

    const socialSelect = document.getElementById('social-vars-select');
    const envSelect = document.getElementById('env-vars-select');

    // Add selected options from social dropdown
    for (const option of socialSelect.selectedOptions) {
        currentSelected.add(option.value);
    }
    // Add selected options from environmental dropdown
    for (const option of envSelect.selectedOptions) {
        currentSelected.add(option.value);
    // Remove activated states if selection changes
    document.getElementById('generate-index').classList.remove('activated');
    document.getElementById('generate-residential').classList.remove('activated');
    }

    updateSelectedBox(); // Update the display box showing selected variables
}

// Update the box showing currently selected variables for index creation
function updateSelectedBox() {
  const selectedBox = document.getElementById('selected-variables');
  selectedBox.innerHTML = ''; // Clear current tags

  currentSelected.forEach(variableId => {
    const tag = document.createElement('div');
    tag.className = 'selected-tag';
    // Use simple friendly name - enhance if needed
    tag.textContent = variableId.replace(/_/g, ' ');
    tag.dataset.value = variableId; // Store the actual value

    // Clicking a tag removes it from selection and deselects in dropdown
    tag.onclick = () => {
      currentSelected.delete(variableId); // Remove from the Set

      // Deselect in the corresponding dropdown
      const socialSelect = document.getElementById('social-vars-select');
      const envSelect = document.getElementById('env-vars-select');
      let optionFound = false;
      for (const option of socialSelect.options) {
          if (option.value === variableId) { option.selected = false; optionFound = true; break; }
      }
      if (!optionFound) {
          for (const option of envSelect.options) {
              if (option.value === variableId) { option.selected = false; break; }
          }
      }
      updateSelectedBox(); // Update the display box again
    };
    selectedBox.appendChild(tag);
  });
}

// ==========================================================
// SINGLE-CLICK MULTI-SELECT HANDLING
// ==========================================================

// --- Helper function to manually update selections and UI ---
function updateMultiSelectState(selectElement) {
    currentSelected.clear(); // Reset the main Set tracker

    // Get ALL select elements to update the Set from scratch
    const socialSelect = document.getElementById('social-vars-select');
    const envSelect = document.getElementById('env-vars-select');

    // Add selected options from social dropdown
    if (socialSelect) {
        for (const option of socialSelect.options) { // Iterate through ALL options
            if (option.selected) { // Check the selected property
                currentSelected.add(option.value);
            }
        }
    }
    // Add selected options from environmental dropdown
    if (envSelect) {
        for (const option of envSelect.options) {
            if (option.selected) {
                currentSelected.add(option.value);
            }
        }
    }

    // Deactivate generate buttons whenever selection might change
    document.getElementById('generate-index')?.classList.remove('activated');
    document.getElementById('generate-residential')?.classList.remove('activated');
    // Also consider resetting index state fully if needed? For now, just visual.
    // setIndexActiveState('activity', false);
    // setIndexActiveState('residential', false);


    updateSelectedBox(); // Update the visual tag display box
    console.log("Current selected variables:", Array.from(currentSelected)); // Log current selection
}


// --- Function to attach single-click listeners ---
function attachSingleClickMultiSelect(selectElement) {
    if (!selectElement) return;

    // Use 'mousedown' + preventDefault to override default multi-select behavior
    selectElement.addEventListener('mousedown', function(event) {
        // Only act if the target was an <option> element
        if (event.target.tagName === 'OPTION') {
            const option = event.target;

            // Prevent the browser's default selection behavior (which often requires Ctrl/Cmd)
            event.preventDefault();

            // Toggle the 'selected' state of the clicked option
            option.selected = !option.selected;

            // Manually trigger the update of our state and UI
            updateMultiSelectState(selectElement);

            // Optional: Keep focus on the select element
            selectElement.focus();
        }
    });

     // Add keyboard support (Spacebar to toggle) - Optional but good UX
     selectElement.addEventListener('keydown', function(event) {
         if (event.key === ' ' || event.key === 'Spacebar') {
             // Find the currently focused option within this select
             const focusedOption = selectElement.querySelector('option:focus');
             if (focusedOption) {
                 event.preventDefault(); // Prevent page scrolling
                 focusedOption.selected = !focusedOption.selected;
                 updateMultiSelectState(selectElement);
             }
         }
     });

     // Note: This simulation might not perfectly replicate all native behaviors
     // (e.g., Shift+Click range selection is not implemented here).
}


// Reset selection for index creation and related states
function resetIndexSelection() {
    console.log("Resetting index selection and related states...");

    // 1. Clear the internal selection set
    currentSelected.clear();

    // 2. Clear the visual display of selected variables FIRST
    updateSelectedBox(); // This now just clears the box visually

    // 3. Deselect all options in both multi-select dropdowns
    const socialSelect = document.getElementById('social-vars-select');
    const envSelect = document.getElementById('env-vars-select');
    if (socialSelect) {
        for (const option of socialSelect.options) { option.selected = false; }
    }
    if (envSelect) {
        for (const option of envSelect.options) { option.selected = false; }
    }

    // 4. Clear Index Name and Description fields
    const indexNameInput = document.getElementById('index-name');
    const indexDescInput = document.getElementById('index-desc');
    if (indexNameInput) indexNameInput.value = '';
    if (indexDescInput) indexDescInput.value = '';

    // 5. Deactivate BOTH index types using the helper function
    // This handles generate buttons, table/hist/analyze/data-download buttons
    setIndexActiveState('residential', false);
    setIndexActiveState('activity', false);

    // 6. Clear the main index info panel
    const indexInfoPanel = document.getElementById('index-info');
    if (indexInfoPanel) {
         // Optionally check if a base variable is active and display that,
         // otherwise show the default message.
         if (activeField && !generatedIndexMetadata.activity.fieldName && !generatedIndexMetadata.residential.fieldName) {
              updateInfoPanelForVariable(activeField); // Show info for base variable if one is displayed
         } else {
              indexInfoPanel.innerHTML = 'Select a variable or generate an index.';
         }
    }

    // 7. Clear Race Analysis State
    removeRaceLegend();
    removeRaceBorderLayer();
    const raceResultPanel = document.getElementById('race-analysis-result');
    if (raceResultPanel) {
        raceResultPanel.innerHTML = 'Select race groups and click an "Analyze" button above.';
    }
    try { // Uncheck race checkboxes
        document.querySelectorAll('.race-checkbox').forEach(checkbox => {
            checkbox.checked = false;
        });
    } catch(e) { console.warn("Could not reset race checkboxes:", e); }
    const raceTableDownloadBtn = document.getElementById('download-race-table');
    if (raceTableDownloadBtn) raceTableDownloadBtn.disabled = true; // Disable race table download

    // 8. Clear Stored Index Metadata (important for downloads)
    generatedIndexMetadata.residential = { name: null, description: null, variables: [], fieldName: null, stats: null };
    generatedIndexMetadata.activity = { name: null, description: null, variables: [], fieldName: null, stats: null };
    // Also clear the global layer objects/field names if you use them elsewhere directly
    activityLayer = null;
    residentialLayer = null;
    activityFieldName = '';
    residentialFieldName = '';


    // 9. Disable Map Image Download Button
    // (Unless you want it enabled if a base variable is still shown)
    const mapDownloadButton = document.getElementById('download-map-image');
    // Let's disable it on reset for simplicity, it will re-enable when a layer is shown.
    if (mapDownloadButton) mapDownloadButton.disabled = true;

    // 10. Optionally Reset Main Map View (if no base variable should remain)
    // If you want the map to become blank or show a default layer on reset:
    // if (geojsonLayer && map.hasLayer(geojsonLayer)) map.removeLayer(geojsonLayer);
    // if (legend && map.hasControl(legend)) map.removeControl(legend);
    // activeField = ''; // Clear the active field tracker
    // map.setView([42.3, -83], 9); // Reset view
    // document.getElementById('field-select').value = ""; // Reset dropdown selection

    console.log("Index reset complete.");
}



// Generate Activity or Residential Index via backend call
// ==========================================================
// COMPLETE generateIndex FUNCTION (Fixed Button Activation)
// ==========================================================

// Assumes global variable `generatedIndexMetadata` is defined like:
// let generatedIndexMetadata = {
//     residential: { name: null, description: null, variables: [], fieldName: null, stats: null },
//     activity: { name: null, description: null, variables: [], fieldName: null, stats: null }
// };
// Assumes helper functions like setIndexActiveState, generateLayerFromField, getDisplayInfoForBaseVar exist.
// Assumes global variables like data, currentSelected, activityLayer, residentialLayer, activityFieldName, residentialFieldName exist.

async function generateIndex(endpoint, isActivity) {
    // --- Get User Input ---
    const nameInput = document.getElementById('index-name');
    const descInput = document.getElementById('index-desc');
    const baseName = nameInput.value.trim();
    const description = descInput.value.trim();
    const variables = Array.from(currentSelected); // Ensure currentSelected is up-to-date

    // --- Determine Index Type and Field Name ---
    const indexType = isActivity ? 'activity' : 'residential';
    // Use baseName (user input) for constructing the field name backend should create
    const indexFieldName = isActivity ? `${baseName}_ACT` : `${baseName}_RES`;

    // --- Clear previous race analysis state ---
    removeRaceLegend();
    removeRaceBorderLayer();
    // Clear any previously stored stats and disable race table download
    if (generatedIndexMetadata.residential) generatedIndexMetadata.residential.stats = null;
    if (generatedIndexMetadata.activity) generatedIndexMetadata.activity.stats = null;
    const raceDownloadBtn = document.getElementById('download-race-table');
    if (raceDownloadBtn) raceDownloadBtn.disabled = true;

    // --- Input Validation ---
    if (!baseName) {
        alert("Please provide a name for the index.");
        nameInput.focus();
        return;
    }
    // Basic name validation (adjust regex if needed)
    if (!/^[a-zA-Z0-9_]+$/.test(baseName)) {
        alert("Index name can only contain letters, numbers, and underscores (_).");
        nameInput.focus();
        return;
    }
    if (variables.length === 0) {
        alert("Please select at least one variable for the index.");
        return;
    }

    console.log(`Attempting to generate index via Worker. Type: ${indexType}, Name: "${baseName}", Expected field: "${indexFieldName}"`);
    
    // --- Store input metadata BEFORE fetch ---
    // This stores what we *expect* the backend to return
    generatedIndexMetadata[indexType] = {
        name: baseName,
        description: description,
        variables: variables,
        fieldName: indexFieldName, // Store the *expected* field name
        stats: null // Clear previous race stats for this index type
    };
    // Disable relevant download button initially for this generation cycle
    const downloadDataButton = document.getElementById(`download-${indexType}-data`);
    if(downloadDataButton) downloadDataButton.disabled = true;


    // --- UI Update: Show Loading ---
    const infoPanel = document.getElementById('index-info');
    if(infoPanel) infoPanel.innerHTML = `Generating index "${indexFieldName}"... Please wait.`;
    // Also visually deactivate generate buttons during generation (optional but good UX)
    document.getElementById('generate-index')?.classList.remove('activated');
    document.getElementById('generate-residential')?.classList.remove('activated');


    // --- Fetch Request ---
    fetch(`${API_BASE_URL}${endpoint}`, { // Use the relative base URL + endpoint path
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        // Send the BASE name and variables to the backend
        body: JSON.stringify({ name: baseName, description: description, variables })
    })
    .then(res => { // Handle HTTP errors
        if (!res.ok) {
            return res.json().then(errData => {
                 // Try to get specific error from backend JSON, otherwise use status
                 throw new Error(errData.error || `Server error generating index. Status: ${res.status}`);
            }).catch(() => {
                 // Fallback if response isn't JSON or errData.error doesn't exist
                 throw new Error(`Server error generating index. Status: ${res.status}`);
            });
        }
        return res.json(); // Parse JSON response
    })
    .then(async geojson => { // Process successful response (async because generateLayerFromField is async)
        // --- Validate response structure ---
        if (!geojson || !geojson.features || geojson.features.length === 0) {
             throw new Error("Received invalid or empty GeoJSON response from server.");
        }
        data = geojson; // Update global data with the FULL response from backend

        console.log(`--- Received GeoJSON after ${indexType} index generation ---`);

        // --- CRITICAL VALIDATION: Check if the expected fieldName exists in the returned data ---
        if (!(data.features[0].properties.hasOwnProperty(indexFieldName))) {
             console.error(`!!! Column '${indexFieldName}' (expected from base name '${baseName}') was NOT FOUND in received GeoJSON properties !!!`);
              // Reset metadata for this type as generation failed effectively
              generatedIndexMetadata[indexType] = { name: null, description: null, variables: [], fieldName: null, stats: null };
             throw new Error(`Generated index column '${indexFieldName}' not found in the response data. Check backend logic or index name.`);
         }
         console.log(`Confirmed column '${indexFieldName}' exists in returned data.`);

        // --- Generate Layer Object (using the confirmed indexFieldName) ---
        console.log(`Calling generateLayerFromField with field: ${indexFieldName} (returnOnly=true)`);
        const layer = await generateLayerFromField(indexFieldName, true); // Use await

        // Handle failure to create layer object (e.g., no numeric data found)
        if (!layer) {
            // Reset metadata as the layer couldn't be created
             generatedIndexMetadata[indexType] = { name: null, description: null, variables: [], fieldName: null, stats: null };
            throw new Error(`Index column "${indexFieldName}" found, but creating the map layer failed (check if data is numeric).`);
        }

        // --- Store Layer and Update Metadata ---
        generatedIndexMetadata[indexType].fieldName = indexFieldName; // Confirm field name in metadata
        let messageVariables = variables.map(varId => (getDisplayInfoForBaseVar(varId)?.name || varId)).join(', ');

        // --- Update UI, store layer, enable buttons ---
        // Activate ONLY the buttons for the index type just generated
        if (isActivity) {
            activityLayer = layer;
            activityFieldName = indexFieldName; // Update global var if used elsewhere
            if(infoPanel) infoPanel.innerHTML =
              `<strong>✅ Activity Index Generated: ${indexFieldName}</strong><br><small><i>Name: ${baseName}, Desc: ${description || 'N/A'}</i></small><br>Variables: ${messageVariables}`;
            setIndexActiveState('activity', true); // Activate activity buttons
        } else { // Residential
            residentialLayer = layer;
            residentialFieldName = indexFieldName; // Update global var if used elsewhere
             if(infoPanel) infoPanel.innerHTML =
               `<strong>🏠 Residential Index Generated: ${indexFieldName}</strong><br><small><i>Name: ${baseName}, Desc: ${description || 'N/A'}</i></small><br>Variables: ${messageVariables}`;
             setIndexActiveState('residential', true); // Activate residential buttons
        }
        // Note: setIndexActiveState(indexType, true) handles enabling the specific download button too

        // --- Display Layer on Main Map ---
        console.log(`Calling generateLayerFromField with field: ${indexFieldName} (returnOnly=false) to display`);
        await generateLayerFromField(indexFieldName, false); // Use await, this updates the main map/activeField

    })
    .catch(err => { // Handle errors from fetch or processing
        console.error(`Failed to generate ${indexType} index:`, err);
        alert(`Failed to generate index: ${err.message}`); // Show user-friendly message
        if(infoPanel) infoPanel.innerHTML = `Error generating index: ${err.message}`;

        // Reset metadata on failure for the type we tried to generate
        generatedIndexMetadata[indexType] = { name: null, description: null, variables: [], fieldName: null, stats: null };

        // Ensure buttons are appropriately disabled/reset on failure
        setIndexActiveState(indexType, false);
    });
} // --- End of generateIndex function ---

// --- Map Comparison Logic ---
let mapLeft, mapRight; // Store comparison map instances

async function setupComparisonMaps() {
    if (!activityLayer || !residentialLayer) {
        alert("Please generate both the Activity Space Index and the Residential Index before comparing.");
        return;
    }
     if (!activityFieldName || !residentialFieldName) {
         alert("Index names are missing. Cannot set up comparison.");
         return;
     }

    document.getElementById('map').classList.add('hidden'); // Hide single map
    document.getElementById('map-wrapper').classList.remove('hidden'); // Show comparison wrapper
    document.getElementById('back-button').classList.remove('hidden'); // Show back button

    // Initialize maps ONLY if they haven't been initialized yet
    if (!mapLeft) {
        mapLeft = L.map('map-left').setView([42.3, -83], 9);
        L.tileLayer('https://{s}.basemaps.cartocdn.com/light_all/{z}/{x}/{y}{r}.png', { attribution: '© CARTO', subdomains: 'abcd', maxZoom: 19 }).addTo(mapLeft);
    }
     if (!mapRight) {
        mapRight = L.map('map-right').setView([42.3, -83], 9);
        L.tileLayer('https://{s}.basemaps.cartocdn.com/light_all/{z}/{x}/{y}{r}.png', { attribution: '© CARTO', subdomains: 'abcd', maxZoom: 19 }).addTo(mapRight);
     }

     // Clear existing layers before adding new ones
     mapLeft.eachLayer(layer => { if (layer instanceof L.GeoJSON) mapLeft.removeLayer(layer); });
     mapRight.eachLayer(layer => { if (layer instanceof L.GeoJSON) mapRight.removeLayer(layer); });

    // Add the stored index layers
    activityLayer.addTo(mapRight );
    residentialLayer.addTo(mapLeft);

    // Update titles
    document.getElementById('map-right-title').textContent = `Activity Space Index: ${activityFieldName}`;
    document.getElementById('map-left-title').textContent = `Residential Index: ${residentialFieldName}`;

    // --- Add Legends to Comparison Maps ---
    try {
        // Now 'await' is valid because the function is async
        const ss = await import('https://cdn.skypack.dev/simple-statistics');

        // Create Left Legend (Residential)
        const resValues = data.features
            .map(f => parseFloat(f.properties[residentialFieldName]))
            .filter(v => !isNaN(v));
        if (resValues.length > 0) {
            const resBreaks = ss.jenks(resValues, 5);
            removeComparisonLegends(); // Remove old before adding new
            legendLeft = createLegendControl(residentialFieldName, resBreaks);
            legendLeft.addTo(mapLeft);
        }

        // Create Right Legend (Activity)
        const actValues = data.features
            .map(f => parseFloat(f.properties[activityFieldName]))
            .filter(v => !isNaN(v));
        if (actValues.length > 0) {
            const actBreaks = ss.jenks(actValues, 5);
            // No need to call removeComparisonLegends again here
            legendRight = createLegendControl(activityFieldName, actBreaks);
            legendRight.addTo(mapRight);
        }
    } catch (e) {
        console.error("Error creating comparison legends:", e);
    }
    // --- End Add Legends ---


    // Fit bounds and Sync maps
    try {
        
        mapLeft.fitBounds(residentialLayer.getBounds());
        mapRight.fitBounds(activityLayer.getBounds());
        // Ensure Leaflet.Sync is loaded and maps are valid Leaflet instances
        if (mapLeft && mapRight && typeof mapLeft.sync === 'function') {
            mapLeft.sync(mapRight);
            mapRight.sync(mapLeft);
        } else {
            console.error("L.Map.Sync is not available or maps are not initialized correctly.");
        }
    } catch (e) {
        console.error("Error fitting bounds or syncing maps:", e);
        // Fallback view
        mapLeft.setView([42.3, -83], 9);
        mapRight.setView([42.3, -83], 9);
    }

     // Invalidate map sizes after container becomes visible
     setTimeout(() => {
         if (mapLeft) mapLeft.invalidateSize();
         if (mapRight) mapRight.invalidateSize();
     }, 100); // Small delay often helps rendering
}

function goBackToSingleMap() {

    document.getElementById('map').classList.remove('hidden'); // Show single map
    document.getElementById('map-wrapper').classList.add('hidden'); // Hide comparison wrapper
    document.getElementById('back-button').classList.add('hidden'); // Hide back button

    removeRaceLegend(); // Already likely removed, but safe to call
    removeRaceBorderLayer();
    removeComparisonLegends();

    // Unsync maps to prevent potential issues
    if (mapLeft && mapRight && typeof mapLeft.unsync === 'function') {
        mapLeft.unsync(mapRight);
        mapRight.unsync(mapLeft);
    }

    // Optional: Destroy comparison maps to free resources if not needed again soon
    // if (mapLeft) { mapLeft.remove(); mapLeft = null; }
    // if (mapRight) { mapRight.remove(); mapRight = null; }

    // Ensure the main map is sized correctly
     if (map) map.invalidateSize();
}


// --- Floating Output Panel (Table/Histogram) ---

// Generic function to render a table for a given field
function renderTableGeneric(field) {
  console.log(`Rendering TABLE for field: ${field}`);
  if (!data || !data.features) {
      alert("No data loaded to create table.");
      return;
  }
  const panel = document.getElementById('floating-output');
  const output = document.getElementById('visual-output');
  const friendlyName = getFriendlyFieldName(field); // <<< Get friendly name
  panel.classList.remove('hidden'); // Make panel visible
  const panelTitle = document.getElementById('floating-panel-title');
  if (panelTitle) panelTitle.innerHTML = `Table: ${friendlyName}`; // Update panel header
  output.innerHTML = `<h4>Table View: ${friendlyName}</h4>`;

  const table = document.createElement('table');
  table.className = 'data-table'; // Add class for styling

  // Create header row
  const thead = table.createTHead();
  const headerRow = thead.insertRow();
  const th1 = document.createElement('th');
  th1.textContent = 'Origin Tract';
  headerRow.appendChild(th1);
  const th2 = document.createElement('th');
  th2.textContent = friendlyName;// Use the field name as header
  headerRow.appendChild(th2);

  // Create body rows
  const tbody = table.createTBody();
  data.features.forEach(f => {
      const row = tbody.insertRow();
      const cell1 = row.insertCell();
      cell1.textContent = f.properties['Origin_tract'] || 'N/A';
      const cell2 = row.insertCell();
      const val = f.properties[field];
      cell2.textContent = (val !== null && val !== undefined && !isNaN(parseFloat(val)))
                          ? parseFloat(val).toFixed(2)
                          : 'N/A';
  });

  output.appendChild(table);
}


// Generic function to render a histogram for a given field
async function renderHistogramGeneric(field) {
  // --- Initial data checks ---
  if (!data || !data.features) {
      alert("No data loaded to create histogram.");
      return;
  }
  const values = data.features
      .map(f => parseFloat(f.properties[field]))
      .filter(v => v !== null && v !== undefined && !isNaN(v));

  if (values.length === 0) {
      // Display message directly in the panel
      const output = document.getElementById('visual-output');
      if(output) { // Check if output element exists
          const panel = document.getElementById('floating-output');
          panel.classList.remove('hidden');
          output.innerHTML = `<h4>Histogram View: ${field}</h4><p>No numeric data available for this histogram.</p>`;
      } else {
          alert("No numeric data available for this histogram.");
      }
      return;
  }
  // --- End Initial checks ---


  // --- Setup Panel and Canvas ---
  const panel = document.getElementById('floating-output');
  const output = document.getElementById('visual-output');
  const friendlyName = getFriendlyFieldName(field); // <<< Get friendly name
  const panelTitle = document.getElementById('floating-panel-title');
  panel.classList.remove('hidden');
  if (panelTitle) panelTitle.innerHTML = `Histogram: ${friendlyName}`; // Update panel header
  output.innerHTML = `<h4>Histogram View: ${friendlyName}</h4>`; // Update content header

  const canvas = document.createElement('canvas');
  // *** FIX: Declare with const ***
  const canvasWidth = 380;
  const canvasHeight = 220;
  // *** END FIX ***
  canvas.width = canvasWidth;
  canvas.height = canvasHeight;
  output.appendChild(canvas);
  const ctx = canvas.getContext('2d');
  // --- End Setup ---


  // --- Calculations ---
  const ss = await import('https://cdn.skypack.dev/simple-statistics');
  const mean = ss.mean(values);

  const bins = 10;
  const min = Math.min(...values);
  const max = Math.max(...values);

  // Handle case where all values are the same
  if (min === max) {
      output.innerHTML += `<p>All values are ${min.toFixed(2)}. Cannot create histogram.</p>`;
      return;
  }

  const step = (max - min) / bins;
  // *** FIX: Initialize histogram array HERE ***
  const histogram = new Array(bins).fill(0);
  const binLabels = new Array(bins);

  // Populate histogram array
  values.forEach(v => {
    let binIndex = Math.floor((v - min) / step);
    if (v === max) { binIndex = bins - 1; }
    binIndex = Math.max(0, Math.min(binIndex, bins - 1));
    histogram[binIndex]++;
  });

  // Create bin labels
   for (let i = 0; i < bins; i++) {
       const binStart = min + i * step;
       const binEnd = min + (i + 1) * step;
       binLabels[i] = `${binStart.toFixed(1)}-${binEnd.toFixed(1)}`;
   }

  // *** FIX: Calculate maxCount AFTER histogram is populated ***
  const maxCount = Math.max(...histogram);
  // *** END FIX ***

  // Check if counts are zero AFTER calculating maxCount
  if (maxCount === 0) {
       output.innerHTML += '<p>No data counts in histogram bins.</p>';
       return;
  }
  // --- End Calculations ---


  // --- Define Chart Area ---
  const marginTop = 10;
  const marginBottom = 50;
  const marginLeft = 45;
  const marginRight = 10;
  const chartWidth = canvasWidth - marginLeft - marginRight;
  const chartHeight = canvasHeight - marginTop - marginBottom;

  const barWidth = chartWidth / bins;
  const scaleY = chartHeight / maxCount; // Calculate scaleY using correct maxCount
  // --- End Define Chart Area ---


  // --- Drawing ---
  // Draw Y-axis labels and lines
  ctx.fillStyle = '#666';
  ctx.font = '10px sans-serif';
  ctx.textAlign = 'right';
  ctx.textBaseline = 'middle';
  const numYLabels = 5;
  for(let i = 0; i <= numYLabels; i++) {
      const val = Math.round(maxCount * i / numYLabels);
      const y = marginTop + chartHeight - (val * scaleY);
      ctx.fillText(val, marginLeft - 5, y);
      ctx.beginPath();
      ctx.moveTo(marginLeft, y);
      ctx.lineTo(marginLeft + chartWidth, y);
      ctx.strokeStyle = '#eee';
      ctx.stroke();
  }

  // Draw Bars
  histogram.forEach((count, i) => {
    const x = marginLeft + i * barWidth;
    const barHeight = count * scaleY;
    const y = marginTop + chartHeight - barHeight;
    ctx.fillStyle = '#4b9cd3';
    ctx.fillRect(x + 1, y, barWidth - 2, barHeight);
  });

  // Draw Mean Line
  if (!isNaN(mean)) {
      const meanX = marginLeft + ((mean - min) / (max - min)) * chartWidth;
      if (meanX >= marginLeft && meanX <= marginLeft + chartWidth) {
          ctx.beginPath();
          ctx.moveTo(meanX, marginTop);
          ctx.lineTo(meanX, marginTop + chartHeight);
          ctx.strokeStyle = '#e63946';
          ctx.lineWidth = 1.5;
          ctx.setLineDash([4, 2]);
          ctx.stroke();
          ctx.setLineDash([]);
          ctx.lineWidth = 1;
          ctx.fillStyle = '#e63946';
          ctx.textAlign = 'center';
          ctx.fillText(`Mean: ${mean.toFixed(1)}`, meanX, marginTop - 5);
      }
  }

  // Draw X-axis labels (Rotated)
  ctx.fillStyle = '#666';
  ctx.textAlign = 'right';
  ctx.textBaseline = 'middle';
  histogram.forEach((count, i) => {
      const x = marginLeft + i * barWidth + (barWidth / 2);
      const y = marginTop + chartHeight + 5;
      const labelText = binLabels[i];
      ctx.save();
      ctx.translate(x, y);
      ctx.rotate(-45 * Math.PI / 180);
      ctx.fillText(labelText, 0, 0);
      ctx.restore();
  });

  // Draw axis lines
   ctx.beginPath();
   ctx.moveTo(marginLeft, marginTop + chartHeight); // X-axis
   ctx.lineTo(marginLeft + chartWidth, marginTop + chartHeight);
   ctx.moveTo(marginLeft, marginTop); // Y-axis
   ctx.lineTo(marginLeft, marginTop + chartHeight);
   ctx.strokeStyle = '#333';
   ctx.stroke();
   // --- End Drawing ---
}


// Close the floating panel
function closeFloatingPanel() {
  const panel = document.getElementById('floating-output');
  panel.classList.add('hidden');
  panel.dataset.currentField = ''; // Clear tracking attribute
}


// --- Race Analysis ---

// Get color for race category
function getRaceColor(race) {
  // Ensure race is lower case for matching
  const lowerRace = typeof race === 'string' ? race.toLowerCase() : 'other';
  return {
    'white': '#1f77b4', // Blue
    'black': '#ff7f0e', // Orange
    'hisp': '#2ca02c', // Green
    'asian': '#d62728', // Red
    'other': '#9467bd'  // Purple
  }[lowerRace] || '#7f7f7f'; // Grey fallback
}

// Perform analysis based on selected race groups and an index field

// --- COMPLETE analyzeByRace function (Updated for Stats Storage & Download Button) ---
function analyzeByRace(indexField) {
    console.log("Attempting to analyze by race. Index Field:", indexField);
    const selectedRaceCheckboxes = document.querySelectorAll('.race-checkbox:checked');
    const selectedRaces = Array.from(selectedRaceCheckboxes).map(cb => cb.value.toLowerCase());
    const mapDownloadButton = document.getElementById('download-map-image');
    const raceTableDownloadBtn = document.getElementById('download-race-table'); // Get race download button

    // --- Basic Input Validations ---
    if (selectedRaces.length === 0) {
        alert("Please select at least one race group to analyze.");
        return;
    }
    if (!indexField) {
        alert("No index field specified for analysis.");
        return;
    }
    if (!data || !data.features) {
        alert("GeoJSON data not available for analysis.");
        return;
    }

    console.log(`Analyzing field "${indexField}" by races: ${selectedRaces.join(', ')}`);

    // --- 1. Reset Previous State & Disable Download ---
    removeRaceBorderLayer(); // Remove any existing border overlay
    removeRaceLegend();      // Remove any existing race legend
    // Ensure race table download is disabled before new stats are calculated
    if (raceTableDownloadBtn) raceTableDownloadBtn.disabled = true;
    // Clear previously stored stats from metadata
    if (generatedIndexMetadata.residential) generatedIndexMetadata.residential.stats = null;
    if (generatedIndexMetadata.activity) generatedIndexMetadata.activity.stats = null;

    // --- Check Map Validity ---
    if (!isValidMap(map)) {
        console.error("Cannot perform race analysis: Leaflet map object is invalid.");
        alert("Map error. Cannot perform race analysis.");
        return;
    }

    // --- 2. Ensure Base Choropleth Layer is Correct ---
    // (Using await here assumes generateLayerFromField might be async, adjust if not)
    // Wrap this part in an async IIFE or make analyzeByRace async if needed
    (async () => {
        if (!geojsonLayer || activeField !== indexField) {
            console.log(`Base layer is not '${indexField}', redrawing.`);
            // Use await if generateLayerFromField is async
            await generateLayerFromField(indexField);
            if (!geojsonLayer) {
                console.error(`Failed to generate base layer for field: ${indexField}`);
                alert(`Could not display the base map layer for ${indexField}. Analysis aborted.`);
                return; // Stop if base layer fails
            }
        } else {
            console.log(`Base layer '${indexField}' is already visible.`);
        }

        // --- 3. Create and Add the NEW Border Overlay Layer ---
        console.log("Creating race border overlay layer.");
        raceBorderLayer = L.geoJson(data, {
            style: feature => {
                const race = (feature.properties['race'] || 'other').toLowerCase();
                const isSelectedRace = selectedRaces.includes(race);
                return {
                    weight: isSelectedRace ? 2.5 : 0.5, // Make selected thicker
                    color: isSelectedRace ? getRaceColor(race) : '#aaa',
                    opacity: 1,
                    dashArray: isSelectedRace ? '' : '4',
                    fillOpacity: 0 // Transparent fill
                };
            },
            onEachFeature: (feature, layer) => {
                const props = feature.properties;
                const tractId = props['Origin_tract'] || 'N/A';
                const valueRaw = props[indexField];
                const valueFormatted = (valueRaw !== null && valueRaw !== undefined && !isNaN(parseFloat(valueRaw)))
                                       ? parseFloat(valueRaw).toFixed(2) : 'N/A';
                const populationRaw = props['population_x_o'];
                const population = (populationRaw !== null && populationRaw !== undefined && !isNaN(parseFloat(populationRaw)))
                                   ? parseFloat(populationRaw).toLocaleString() : 'N/A';
                const countyFips = props['COUNTYFP'];
                const countyName = countyFips ? (countyMapping[countyFips] || `Unknown (${countyFips})`) : 'N/A';
                const rawRace = props['race'];
                const formattedRace = formatRaceName(rawRace);
                let friendlyIndexFieldName = getFriendlyFieldName(indexField) || indexField; // Use helper

                let tooltipContent = `<strong>Tract:</strong> ${tractId}<br>`;
                tooltipContent += `<strong>County:</strong> ${countyName}<br>`;
                if (props.hasOwnProperty('race')) {
                     tooltipContent += `<strong>Dominant Race Group:</strong> ${formattedRace}<br>`; // Changed label slightly
                }
                tooltipContent += `<strong>Population:</strong> ${population}<br>`;
                tooltipContent += `<strong>${friendlyIndexFieldName}:</strong> ${valueFormatted}`;
                layer.bindTooltip(tooltipContent);
            },
            pane: 'shadowPane' // Ensure it renders correctly relative to choropleth
        }).addTo(map);

        // --- Ensure map image download is enabled (since a map is showing) ---
        if (mapDownloadButton) mapDownloadButton.disabled = false;

        // --- 4. Calculate Statistics ---
        const calculatedStats = {}; // Renamed from 'stats' to avoid confusion with global
        const allValuesForIndex = [];

        console.log("Calculating statistics...");
        import('https://cdn.skypack.dev/simple-statistics').then(ss => {
            // Loop through selected races
            selectedRaces.forEach(race => {
                // ... (calculate stats for each race and store in calculatedStats[race]) ...
                const featuresForRace = data.features.filter(f => (f.properties['race'] || 'other').toLowerCase() === race);
                const values = featuresForRace.map(f => parseFloat(f.properties[indexField])).filter(v => !isNaN(v));
                if (values.length > 1) {
                    calculatedStats[race] = { count: values.length, median: ss.median(values).toFixed(2), iqr: ss.interquartileRange(values).toFixed(2), mean: ss.mean(values).toFixed(2) };
                } else if (values.length === 1) {
                     calculatedStats[race] = { count: 1, median: values[0].toFixed(2), iqr: 'N/A', mean: values[0].toFixed(2) };
                } else {
                    calculatedStats[race] = { count: 0, median: 'N/A', iqr: 'N/A', mean: 'N/A' };
                }
            });

            // Calculate overall stats
            data.features.forEach(f => {
                 const val = parseFloat(f.properties[indexField]);
                 if (!isNaN(val)) allValuesForIndex.push(val);
            });
            if (allValuesForIndex.length > 1) {
                calculatedStats['all_tracts'] = { count: allValuesForIndex.length, median: ss.median(allValuesForIndex).toFixed(2), iqr: ss.interquartileRange(allValuesForIndex).toFixed(2), mean: ss.mean(allValuesForIndex).toFixed(2) };
            } else if (allValuesForIndex.length === 1) {
                 calculatedStats['all_tracts'] = { count: 1, median: allValuesForIndex[0].toFixed(2), iqr: 'N/A', mean: allValuesForIndex[0].toFixed(2) };
            } else {
                calculatedStats['all_tracts'] = { count: 0, median: 'N/A', iqr: 'N/A', mean: 'N/A' };
            }

            console.log("Stats calculation complete. Calculated Stats:", calculatedStats);

            // --- Determine indexType for storing stats ---
            let indexType = null;
             // Check against the stored field names in metadata
            if (generatedIndexMetadata.residential && indexField === generatedIndexMetadata.residential.fieldName) {
                indexType = 'residential';
            } else if (generatedIndexMetadata.activity && indexField === generatedIndexMetadata.activity.fieldName) {
                 indexType = 'activity';
            }

            // --- STORE the calculated stats ---
            if (indexType) {
                generatedIndexMetadata[indexType].stats = calculatedStats; // Store the results
                console.log(`Stored stats in generatedIndexMetadata.${indexType}.stats`); // Confirm storage

                // --- Enable Download Button ---
                if(raceTableDownloadBtn){
                     console.log("Attempting to ENABLE race table download button.");
                     raceTableDownloadBtn.disabled = false; // Enable download button
                } else {
                     console.error("Could not find race table download button to enable.");
                }

            } else {
                 console.warn("Stats calculated but could not link analyzed field back to generated index metadata - download disabled.");
                 // Keep button disabled if we couldn't link
                 if(raceTableDownloadBtn) raceTableDownloadBtn.disabled = true;
            }

            // --- 5. Display Statistics Table ---
            showRaceStats(calculatedStats, indexField); // Pass the newly calculated stats

            // --- 6. Add Race Legend ---
            addRaceLegend(selectedRaces);

        }).catch(err => {
            console.error("Error loading or using simple-statistics:", err);
            alert("Could not calculate statistics for race analysis.");
            // Clean up layers/legends if stats fail
            removeRaceBorderLayer();
            removeRaceLegend();
            // Keep download button disabled
            if(raceTableDownloadBtn) raceTableDownloadBtn.disabled = true;
        });
    })().catch(err => {
         // Catch errors from the async IIFE (e.g., if generateLayerFromField fails)
         console.error("Error during race analysis setup:", err);
    });
} // --- End of analyzeByRace function ---


// Display race analysis statistics in the sidebar panel
function showRaceStats(stats, indexField) {
  const panel = document.getElementById('race-analysis-result');
  panel.innerHTML = `<h4>Race Group Stats for ${indexField}</h4>`; // Clear previous and add title

  const table = document.createElement('table');
  table.className = 'data-table'; // Style the table

  // Header
  const thead = table.createTHead();
  const headerRow = thead.insertRow();
  ['Group', 'Tract Count', 'Median', 'IQR', 'Mean'].forEach(headerText => {
      const th = document.createElement('th');
      th.textContent = headerText;
      headerRow.appendChild(th);
  });

  // Body - ensure 'all_tracts' comes last if present
  const tbody = table.createTBody();
  const groups = Object.keys(stats).filter(g => g !== 'all_tracts');
  if (stats['all_tracts']) groups.push('all_tracts'); // Add 'all_tracts' to the end

  groups.forEach(group => {
      const s = stats[group];
      const row = tbody.insertRow();
      row.insertCell().textContent = group.replace('_', ' '); // Make 'all_tracts' readable
      row.insertCell().textContent = s.count;
      row.insertCell().textContent = s.median;
      row.insertCell().textContent = s.iqr;
      row.insertCell().textContent = s.mean;
      // Add color indicator
      const colorCell = row.insertCell();
      const colorSwatch = document.createElement('span');
      colorSwatch.style.display = 'inline-block';
      colorSwatch.style.width = '15px';
      colorSwatch.style.height = '15px';
      colorSwatch.style.backgroundColor = getRaceColor(group);
      colorSwatch.style.border = '1px solid #ccc';
      colorSwatch.style.marginLeft = '5px';
      // Only add swatch for actual race groups, not 'all_tracts'
      if (group !== 'all_tracts') {
          row.cells[0].appendChild(colorSwatch); // Add swatch next to group name
      }

  });

  panel.appendChild(table);
}


// --- Helper function to trigger file download ---
function downloadData(dataString, filename, mimeType = 'text/plain') {
    const blob = new Blob([dataString], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a); // Required for Firefox
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url); // Clean up
}

// ==========================================================
// FUNCTION TO DOWNLOAD MAP AS IMAGE
// ==========================================================
function downloadMapImage() {
    const mapToCapture = map; // Use the main map instance
    const mapDownloadButton = document.getElementById('download-map-image');

    if (!mapToCapture) {
        alert("Map is not initialized.");
        return;
    }
    if (typeof leafletImage !== 'function') {
        alert("Map image library (leaflet-image) not loaded correctly.");
        return;
    }

    // --- Determine a suitable filename ---
    let filename = "map_export";
    if (activeField) {
        // Use the friendly name if possible, otherwise the field ID
        const friendlyName = getFriendlyFieldName(activeField) || activeField;
        // Sanitize filename (remove spaces, special chars)
        filename = friendlyName.replace(/[^a-zA-Z0-9_-]/g, '_').replace(/_+/g, '_');
    }
    // Add suffix if race analysis is active (check if border layer exists)
    if (raceBorderLayer && map.hasLayer(raceBorderLayer)) {
         filename += "_race_analysis";
    }
    filename += ".png";
    // --- End filename logic ---


    // --- Disable button and show loading state (optional) ---
    if (mapDownloadButton) {
        mapDownloadButton.disabled = true;
        mapDownloadButton.innerHTML = '<i class="bi bi-hourglass-split"></i> Processing...';
    }
    const infoPanel = document.getElementById('index-info'); // Or another status area
    const originalInfo = infoPanel ? infoPanel.innerHTML : '';
    if(infoPanel) infoPanel.innerHTML = 'Generating map image... Please wait.';

    console.log("Attempting map image capture...");

    // --- Call leaflet-image ---
    leafletImage(mapToCapture, function(err, canvas) {
        // --- Restore button state and info panel ---
         if (mapDownloadButton) {
             mapDownloadButton.disabled = false; // Re-enable even on error
             mapDownloadButton.innerHTML = '<i class="bi bi-image"></i> Map Image';
         }
         if(infoPanel) infoPanel.innerHTML = originalInfo; // Restore original info text

        // --- Handle results ---
        if (err) {
            console.error("Map image generation failed:", err);
            // Common errors: CORS issues with tiles, library loading problems
            alert(`Failed to generate map image.\nError: ${err.message}\n\nThis might be due to restrictions on loading external map tiles (CORS). Check the browser console for details.`);
            return;
        }

        // --- Success: Trigger download ---
        console.log("Map image canvas created successfully.");
        try {
            const dataUrl = canvas.toDataURL('image/png');
            const a = document.createElement('a');
            a.href = dataUrl;
            a.download = filename;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            console.log(`Map image download triggered as ${filename}`);
        } catch (e) {
            console.error("Error triggering download from canvas:", e);
            alert("Could not trigger map image download after generation.");
        }
    });
}

// --- Helper function to format metadata for CSV ---
function generateMetadataHeader() {
    let header = "# Southeast Michigan Health Equity Viewer Data Export\n";
    header += `# Generated on: ${new Date().toISOString()}\n`;
    header += "# --------------------------------------------------\n\n";

    // Add User Manual Content
    const helpContentElement = document.getElementById('help-content');
    if (helpContentElement) {
        header += "# User Manual / Index Calculation Methods:\n";
        header += "# ----------------------------------------\n";
        // Simple text extraction, replace HTML tags crudely
        let manualText = helpContentElement.innerText || helpContentElement.textContent || '';
        manualText = manualText.replace(/(\r\n|\r|\n)+/g, '\n# '); // Add comment marker to each line
        header += `# ${manualText}\n\n`;
    }

    // Add Variable Definitions Table
    header += "# Variable Definitions:\n";
    header += "# ---------------------\n";
    header += "# ID, Full Name\n";
    for (const group in displayableVariables) {
        displayableVariables[group].forEach(variable => {
             header += `# "${variable.id}", "${variable.name.replace(/"/g, '""')}"\n`; // Escape quotes in name if any
        });
    }
     // Add generated index definitions if they exist
     if (generatedIndexMetadata.residential.fieldName) {
         header += `# "${generatedIndexMetadata.residential.fieldName}", "${generatedIndexMetadata.residential.name || 'Residential Index'} (${generatedIndexMetadata.residential.description || 'User-defined'})"\n`;
     }
     if (generatedIndexMetadata.activity.fieldName) {
         header += `# "${generatedIndexMetadata.activity.fieldName}", "${generatedIndexMetadata.activity.name || 'Activity Index'} (${generatedIndexMetadata.activity.description || 'User-defined'})"\n`;
     }
    header += "# --------------------------------------------------\n\n";

    return header;
}


// --- Event Listeners Setup ---
function attachEventListeners() {
    console.log("Attaching event listeners..."); // Log when function starts

    // Helper function to safely add listener
    function safeAddListener(id, event, handler) {
        const element = document.getElementById(id);
        if (element) {
            element.addEventListener(event, handler);
        } else {
            console.warn(`Element with ID '${id}' not found. Cannot attach listener.`);
        }
    }

    // --- Main variable selection dropdown ---
    safeAddListener('field-select', 'change', e => {
        removeRaceLegend();
        removeRaceBorderLayer();
        // Deactivate generate buttons visually when changing base variable
        document.getElementById('generate-index')?.classList.remove('activated');
        document.getElementById('generate-residential')?.classList.remove('activated');
        // Consider also resetting index state via setIndexActiveState if appropriate
        // setIndexActiveState('activity', false);
        // setIndexActiveState('residential', false);

        const selectedField = e.target.value;
        if (selectedField) {
            generateLayerFromField(selectedField); // This updates activeField internally
            updateInfoPanelForVariable(selectedField);
        } else {
            if (geojsonLayer && map.hasLayer(geojsonLayer)) map.removeLayer(geojsonLayer);
            if (legend && map.hasControl(legend)) map.removeControl(legend); // Safer check
            document.getElementById('index-info').innerHTML = 'Select a variable or generate an index.';
            activeField = '';
        }
    });

    // --- Index creation buttons ---
    safeAddListener('reset-selection', 'click', resetIndexSelection); // Ensure resetIndexSelection also calls setIndexActiveState(false) for both and disables download buttons
    safeAddListener('generate-index', 'click', () => generateIndex('/generate_index', true));
    safeAddListener('generate-residential', 'click', () => generateIndex('/generate_residential_index', false));

    // --- Map comparison buttons ---
    safeAddListener('compare-maps', 'click', setupComparisonMaps);
    safeAddListener('back-button', 'click', goBackToSingleMap);

    // --- Floating panel (Table/Histogram) buttons ---
    safeAddListener('show-table-var', 'click', () => {
        if (!activeField) { alert("No variable or index is currently displayed."); return; }
        closeFloatingPanel(); // Close first to ensure clean state
        renderTableGeneric(activeField);
    });
    safeAddListener('show-histogram-var', 'click', () => {
         if (!activeField) { alert("No variable or index is currently displayed."); return; }
         closeFloatingPanel();
         renderHistogramGeneric(activeField); // Make sure this is async if it uses await
    });
    safeAddListener('show-table-activity', 'click', () => {
        const fieldName = generatedIndexMetadata.activity.fieldName; // Use stored metadata
        if (!fieldName) { alert("Activity index not generated yet."); return; }
        closeFloatingPanel();
        renderTableGeneric(fieldName);
    });
    safeAddListener('show-histogram-activity', 'click', () => {
        const fieldName = generatedIndexMetadata.activity.fieldName;
        if (!fieldName) { alert("Activity index not generated yet."); return; }
        closeFloatingPanel();
        renderHistogramGeneric(fieldName);
    });
    safeAddListener('show-table-residential', 'click', () => {
        const fieldName = generatedIndexMetadata.residential.fieldName;
        if (!fieldName) { alert("Residential index not generated yet."); return; }
        closeFloatingPanel();
        renderTableGeneric(fieldName);
    });
    safeAddListener('show-histogram-residential', 'click', () => {
        const fieldName = generatedIndexMetadata.residential.fieldName;
        if (!fieldName) { alert("Residential index not generated yet."); return; }
        closeFloatingPanel();
        renderHistogramGeneric(fieldName);
    });

    // --- Close floating panel button ---
    safeAddListener('close-output', 'click', closeFloatingPanel);

    // --- Race analysis buttons (Handles switch from compare view) ---
     safeAddListener('analyze-activity', 'click', () => {
        const fieldName = generatedIndexMetadata.activity.fieldName; // Get field from metadata
        if (!fieldName) {
            alert("Please generate the Activity Space Index first.");
            return;
        }
        // Check if in comparison view
        if (!document.getElementById('map-wrapper').classList.contains('hidden')) {
            console.log("In compare view, switching back to single map before race analysis.");
            goBackToSingleMap();
            setTimeout(() => analyzeByRace(fieldName), 150); // Delay analysis slightly
        } else {
            analyzeByRace(fieldName); // Proceed directly
        }
     });
     safeAddListener('analyze-residential', 'click', () => {
        const fieldName = generatedIndexMetadata.residential.fieldName; // Get field from metadata
        if (!fieldName) {
            alert("Please generate the Residential Index first.");
            return;
        }
         // Check if in comparison view
        if (!document.getElementById('map-wrapper').classList.contains('hidden')) {
            console.log("In compare view, switching back to single map before race analysis.");
            goBackToSingleMap();
            setTimeout(() => analyzeByRace(fieldName), 150); // Delay analysis slightly
        } else {
            analyzeByRace(fieldName); // Proceed directly
        }
     });

    // --- Race checkbox change listener ---
     try {
         document.querySelectorAll('.race-checkbox').forEach(checkbox => {
             checkbox.addEventListener('change', () => {
                 // Reset result panel and disable download when selection changes
                 const raceResultPanel = document.getElementById('race-analysis-result');
                 if (raceResultPanel) {
                     raceResultPanel.innerHTML = 'Select race groups and click an "Analyze" button above.';
                 }
                 const raceDownloadBtn = document.getElementById('download-race-table');
                 if (raceDownloadBtn) raceDownloadBtn.disabled = true;
                 // Clear stored stats as they are now invalid
                  if (generatedIndexMetadata.residential) generatedIndexMetadata.residential.stats = null;
                  if (generatedIndexMetadata.activity) generatedIndexMetadata.activity.stats = null;
                  // Optionally remove border layer and legend immediately
                  // removeRaceBorderLayer();
                  // removeRaceLegend();
             });
         });
     } catch (e) {
         console.warn("Could not attach listeners to '.race-checkbox' elements:", e);
     }

    // --- Help Panel Toggle & Draggable ---
    const helpIcon = document.getElementById('help-icon');
    const helpPanel = document.getElementById('help-panel');
    const closeHelpButton = document.getElementById('close-help-panel');
    const helpHeader = helpPanel ? helpPanel.querySelector('.floating-header') : null;

    if (helpIcon && helpPanel && closeHelpButton && helpHeader) {
        console.log("Attaching help panel listeners and making draggable.");
        helpIcon.addEventListener('click', (event) => {
            event.stopPropagation();
            helpPanel.classList.toggle('hidden');
        });
        closeHelpButton.addEventListener('click', () => {
            helpPanel.classList.add('hidden');
        });
        document.addEventListener('click', (event) => {
            if (!helpPanel.classList.contains('hidden') && !helpPanel.contains(event.target) && event.target !== helpIcon) {
                helpPanel.classList.add('hidden');
            }
        });
        makeDraggable(helpPanel, helpHeader); // Make draggable
    } else {
        console.warn("Help panel elements (including header) not all found.");
    }
    // --- End Help Panel ---

    // --- Make Output Panel Draggable ---
    const outputPanel = document.getElementById('floating-output');
    const outputHeader = outputPanel ? outputPanel.querySelector('.floating-header') : null;
    const closeOutputButton = document.getElementById('close-output');

    if (outputPanel && outputHeader && closeOutputButton) {
         console.log("Making output panel draggable.");
         makeDraggable(outputPanel, outputHeader); // Make draggable
         // Ensure close listener is attached (using safeAddListener is better)
         safeAddListener('close-output', 'click', closeFloatingPanel);
    } else {
         console.warn("Output panel elements (including header) not all found. Cannot make draggable.");
    }
    // --- End Output Panel Draggable ---

    // --- Download Button Listeners ---
    safeAddListener('download-residential-data', 'click', () => downloadIndexDataCSV('residential'));
    safeAddListener('download-activity-data', 'click', () => downloadIndexDataCSV('activity'));
    safeAddListener('download-race-table', 'click', downloadRaceAnalysisCSV);
    safeAddListener('download-map-image', 'click', downloadMapImage);


    // --- Listener for Clicking Selected Variable Tags (Map Update) ---
    // NB: This listener might conflict with removal logic in updateSelectedBox
    // unless updateSelectedBox is modified to use a separate remove icon.
    // Consider the UX: Does clicking the tag update the map AND remove it,
    // or should they be separate actions?
    const selectedVariablesContainer = document.getElementById('selected-variables');
    const mainFieldSelect = document.getElementById('field-select');

    if (selectedVariablesContainer && mainFieldSelect) {
        console.log("Attaching listener for variable tag clicks."); // Log attachment attempt
        selectedVariablesContainer.addEventListener('click', (event) => {
            // Check if the click target is the tag itself (or potentially text within it)
             let tagElement = null;
             if (event.target.classList.contains('selected-tag')) {
                 tagElement = event.target;
             } else if (event.target.parentElement?.classList.contains('selected-tag')) {
                  // Allow clicking on text span inside if structure changes later
                  tagElement = event.target.parentElement;
             }
             // IMPORTANT: Ignore clicks on any 'remove' button/icon if you add one later
             if (tagElement && !event.target.classList.contains('remove-tag-btn')) { // Example class for remove icon
                console.log("Tag clicked:", tagElement); // Log the clicked tag element
                const selectedIndexVarId = tagElement.dataset.value;

                if (!selectedIndexVarId) {
                    console.error("Clicked tag is missing data-value attribute:", tagElement);
                    return;
                }

                // --- Logic to find the original display variable name (ending in '_o') ---
                let originalDisplayVarId = '';
                // Add robust logic here based on displayableVariables and naming conventions
                // Example:
                const potentialDirectO = `${selectedIndexVarId}_o`;
                let foundDirectO = false;
                 for (const group in displayableVariables) {
                     if (displayableVariables[group].some(v => v.id === potentialDirectO)) {
                         originalDisplayVarId = potentialDirectO;
                         foundDirectO = true; break;
                     }
                 }
                 if (!foundDirectO) { /* ... add more complex checking logic ... */
                     // Fallback or check if selectedIndexVarId already ends in _o
                      if (selectedIndexVarId.endsWith('_o')) {
                          originalDisplayVarId = selectedIndexVarId;
                      } else {
                           console.warn(`Could not determine _o variable for ${selectedIndexVarId}. Map update may fail.`);
                            originalDisplayVarId = potentialDirectO; // Try anyway? Or fail?
                      }
                 }
                 console.log(`Determined Original Display Var: ${originalDisplayVarId}`);

                // --- Update the map and dropdown ---
                const optionExists = [...mainFieldSelect.options].some(opt => opt.value === originalDisplayVarId);

                if (optionExists) {
                    mainFieldSelect.value = originalDisplayVarId;
                    generateLayerFromField(originalDisplayVarId); // Update map
                    updateInfoPanelForVariable(originalDisplayVarId); // Update info panel
                    // Clear race analysis state
                    removeRaceLegend();
                    removeRaceBorderLayer();
                    // Deactivate generate buttons visually
                     document.getElementById('generate-index')?.classList.remove('activated');
                     document.getElementById('generate-residential')?.classList.remove('activated');
                    // Consider resetting index state:
                    // setIndexActiveState('activity', false);
                    // setIndexActiveState('residential', false);
                    // Disable download buttons if state is fully reset
                     document.getElementById('download-residential-data').disabled = true;
                     document.getElementById('download-activity-data').disabled = true;
                     document.getElementById('download-race-table').disabled = true;


                } else {
                    console.error(`Original display variable '${originalDisplayVarId}' not found in dropdown.`);
                    updateInfoPanel(`Error: Could not find original data for selected variable.`);
                }

                // Prevent the removal logic in updateSelectedBox if it uses tag.onclick
                event.stopPropagation();
            }
        });
    } else {
        console.warn("Could not find #selected-variables or #field-select. Tag click listener not added.");
    }
    // --- End Tag Click Listener ---

    console.log("Event listeners attachment finished."); // Log when function ends
} // --- End of attachEventListeners function ---