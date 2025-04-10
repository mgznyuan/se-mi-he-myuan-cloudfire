// functions/api/[[path]].js

import { Router, error, json } from 'itty-router';
import * as duckdb from '@duckdb/duckdb-wasm'; // Import duckdb-wasm

// --- Configuration ---
const GEOJSON_OBJECT_KEY = 'data_residential.geojson';
const PARQUET_OBJECT_KEY = 'full_data.parquet'; // Key for the Parquet file in R2

// --- CORS Headers ---
const corsHeaders = { /* ... */ };

// --- Router Setup ---
const router = Router();

// --- DuckDB WASM Initialization Helper ---
// Cache the initialized DB instance to avoid re-init on every request if possible
// NOTE: Worker instance lifecycle varies. This might re-initialize frequently.
let dbInstance = null;
let dbInitializing = null; // Promise to prevent race conditions

async function getDb(env) {
    // Race condition prevention and instance caching
    if (dbInitializing) {
        console.log("DuckDB-WASM initialization already in progress, waiting...");
        return await dbInitializing;
    }
    if (dbInstance) {
        // console.log("Returning cached DuckDB-WASM instance.");
        return dbInstance;
    }

    console.log("Attempting DuckDB-WASM initialization...");
    dbInitializing = (async () => {
        try {
            const JSDELIVR_BUNDLES = duckdb.getJsDelivrBundles();
            const bundle = await duckdb.selectBundle(JSDELIVR_BUNDLES);
            // Use default base path (usually fine for Pages Functions)
            const worker_url = URL.createObjectURL(
                 new Blob([`importScripts("${bundle.mainWorker}");`], { type: 'text/javascript' })
             );

            const worker = new Worker(worker_url);
            const logger = new duckdb.ConsoleLogger(); // Logs DuckDB messages to worker console
            const db = new duckdb.AsyncDuckDB(logger, worker);

            await db.instantiate(bundle.mainModule, bundle.pthreadWorker);
            URL.revokeObjectURL(worker_url); // Clean up blob URL

            // Optional: Configure DuckDB extension loading or other settings if needed
            // await db.open({ query: { castTimestampToDate: true } });

            console.log("DuckDB-WASM Initialized Successfully.");
            dbInstance = db;
            return db;
        } catch (err) {
            console.error("DuckDB-WASM Initialization Failed:", err);
            dbInstance = null; // Reset on failure
            throw new Error(`Failed to initialize query engine: ${err.message}`);
        } finally {
            dbInitializing = null; // Clear the promise lock
        }
    })();

    return await dbInitializing;
}

// Close DB connection helper (call this if you explicitly open one)
async function closeDbConnection(conn) {
    if (conn) {
        try {
            await conn.close();
            // console.log("DuckDB connection closed.");
        } catch (e) {
            console.error("Error closing DuckDB connection:", e);
        }
    }
}


// --- Helper Functions ---
// --- Helper Functions ---

/**
 * Cleans a user-provided name to be suitable for use as a column name suffix or part of a filename.
 * Removes leading/trailing spaces, replaces internal whitespace with underscores,
 * and removes characters other than letters, numbers, and underscores.
 * Provides a fallback if the result is empty.
 * @param {string} name - The input name string.
 * @returns {string} The cleaned name.
 */
function cleanIndexName(name) {
    if (typeof name !== 'string' || !name) {
        return `invalid_name_${Date.now()}`; // Fallback for null/empty input
    }
    // Trim -> Replace whitespace with _ -> Remove non-alphanumeric/underscore chars
    const cleaned = name.trim()
                       .replace(/\s+/g, '_')
                       .replace(/[^\w_]/g, ''); // \w is letters, numbers, underscore

    // Handle cases where cleaning results in an empty string (e.g., input was "!@#$")
    return cleaned || `invalid_name_${Date.now()}`;
}

/**
 * Securely verifies a provided passcode against a stored SHA-256 hash.
 * @param {string} providedPasscode - The passcode entered by the user.
 * @param {string} storedHash - The SHA-256 hex string stored as a Worker secret.
 * @returns {Promise<boolean>} True if the passcode matches the hash, false otherwise.
 */

async function verifyPasscode(providedPasscode, storedHash) {
    if (!providedPasscode || typeof providedPasscode !== 'string' || !storedHash || typeof storedHash !== 'string') {
        console.error("verifyPasscode: Invalid input provided.");
        return false;
    }
    // Ensure storedHash is lowercase for consistent comparison
    storedHash = storedHash.toLowerCase();

    try {
        // 1. Encode the provided passcode into a buffer
        const encoder = new TextEncoder();
        const data = encoder.encode(providedPasscode);

        // 2. Hash the provided passcode using SHA-256 with Web Crypto API
        //    (Available in Workers environment)
        const hashBuffer = await crypto.subtle.digest('SHA-256', data);

        // 3. Convert the resulting ArrayBuffer to a hexadecimal string
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        const calculatedHashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');

        // 4. Compare the calculated hash with the stored hash
        //    (This is a basic comparison, not strictly constant-time, but generally acceptable here)
        if (calculatedHashHex === storedHash) {
            // console.log("Passcode verification successful."); // Optional debug log
            return true;
        } else {
            console.log("Passcode verification failed: Hashes do not match."); // Log failure for debugging
            return false;
        }

    } catch (error) {
        console.error("Error during passcode hash verification:", error);
        return false; // Fail securely on any error during the process
    }
}

/**
 * Fetches an object from an R2 bucket binding and parses its body.
 * @param {object} env - The Worker environment object containing bindings.
 * @param {string} bindingName - The name of the R2 bucket binding in wrangler.toml/Pages settings.
 * @param {string} objectKey - The key (path/filename) of the object within the R2 bucket.
 * @param {'json' | 'text' | 'arrayBuffer' | 'blob' | 'stream'} [responseType='json'] - How to parse the R2Object body. Defaults to 'json'. Use 'stream' to get the ReadableStream.
 * @returns {Promise<object | string | ArrayBuffer | Blob | ReadableStream>} The fetched and parsed object, or the R2Object itself on error.
 * @throws {Error} If the binding is missing, the object is not found, or parsing fails.
 */
async function getR2Object(env, bindingName, objectKey, responseType = 'json') {
    const bucket = env[bindingName];
    if (!bucket) {
        const errorMsg = `R2 bucket binding '${bindingName}' not configured in Worker environment.`;
        console.error(errorMsg);
        // Throw a specific error type or message that can be caught upstream
        throw new Error(errorMsg); // Indicate a server configuration problem
    }

    console.log(`Attempting to fetch R2 object: Binding='${bindingName}', Key='${objectKey}', Type='${responseType}'`);
    const object = await bucket.get(objectKey);

    if (object === null) {
        const errorMsg = `Required data file '${objectKey}' not found in R2 bucket bound to '${bindingName}'.`;
        console.error(errorMsg);
        // Throw an error that indicates resource not found (can translate to 404)
        const err = new Error(errorMsg);
        err.status = 404; // Add status for potential upstream handling
        throw err;
    }

    console.log(`Successfully retrieved R2 object '${objectKey}'. Size: ${object.size} bytes.`);

    try {
        // R2Object provides methods to read the body in different formats
        switch (responseType) {
            case 'json':
                return await object.json();
            case 'text':
                return await object.text();
            case 'arrayBuffer':
                return await object.arrayBuffer();
            case 'blob': // Less common for worker processing, useful for passthrough
                return await object.blob();
            case 'stream': // For large files if processing chunk by chunk
                 return object.body; // Return the ReadableStream
            default:
                console.warn(`Unsupported responseType '${responseType}' requested for R2 object '${objectKey}'. Returning raw R2Object.`);
                return object; // Return the R2Object itself if type is unknown/unsupported
        }
    } catch (e) {
        const errorMsg = `Failed to parse R2 object '${objectKey}' (binding '${bindingName}') as ${responseType}: ${e.message}`;
        console.error(errorMsg, e);
        throw new Error(errorMsg); // Indicate a data processing/format error
    }
}


/**
 * Calculates the underlying residential index for a given feature based on selected variables' Z-scores.
 * This index is typically the average of the relevant _zscore_o columns multiplied by 100.
 * @param {object} feature - A GeoJSON feature object, expected to have a `properties` object.
 * @param {string[]} selectedVarsJS - Array of JS variable names selected by the user (e.g., 'poverty_rate').
 * @returns {number | null} The calculated index value or null if calculation fails or no valid data is found.
 */
function calculateUnderlyingResidentialIndex(feature, selectedVarsJS) {
    if (!feature?.properties || !Array.isArray(selectedVarsJS) || selectedVarsJS.length === 0) {
        // console.warn("Cannot calculate residential index: Invalid feature or no variables selected.");
        return null;
    }

    let zscoreSum = 0;
    let zscoreCount = 0;

    selectedVarsJS.forEach(jsVar => {
        // Construct the expected Z-score column name (_o suffix for origin/residential)
        // Adjust this mapping logic if your column names differ significantly
        const zscoreColName = `${jsVar.replace(/ /g, '')}_zscore_o`;

        if (feature.properties.hasOwnProperty(zscoreColName)) {
            const value = parseFloat(feature.properties[zscoreColName]);
            if (!isNaN(value)) { // Check if the parsed value is a valid number
                zscoreSum += value;
                zscoreCount++;
            } else {
                // Optional: Log if a z-score column exists but isn't numeric
                // console.log(`Feature ${feature.properties['Origin_tract']}: Non-numeric value in ${zscoreColName}`);
            }
        } else {
            // Optional: Log if a required z-score column is missing for this feature
            // console.log(`Feature ${feature.properties['Origin_tract']}: Missing expected column ${zscoreColName}`);
        }
    });

    if (zscoreCount > 0) {
        const averageZscore = zscoreSum / zscoreCount;
        return averageZscore * 100; // Multiply by 100 as per formula description
    } else {
        // No valid Z-score values were found for the selected variables in this feature
        // console.warn(`Feature ${feature.properties['Origin_tract']}: No valid z-score data found for selected variables.`);
        return null; // Return null to indicate calculation wasn't possible
    }
}

// --- Middleware ---
router.options('*', () => new Response(null, { headers: corsHeaders })); // CORS Preflight


// --- API Routes ---

// POST /api/login
router.post('/api/login', async (request, env) => {
    try {
        const { passcode } = await request.json();
        const storedHash = env.PASSCODE_HASH; // From Worker secrets

        if (!storedHash) {
            console.error("PASSCODE_HASH secret not set.");
            return error(500, 'Server configuration error.', { headers: corsHeaders });
        }

        const isValid = await verifyPasscode(passcode, storedHash); // Use await for async crypto

        if (isValid) {
            return json({ success: true }, { headers: corsHeaders });
        } else {
            // Use 401 Unauthorized status code
            return new Response(JSON.stringify({ success: false, error: 'Invalid passcode.' }), {
                status: 401,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }
    } catch (err) {
        console.error("Login error:", err);
        // Use 500 Internal Server Error status code
        return new Response(JSON.stringify({ success: false, error: 'Server error during login.' }), {
            status: 500,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
    }
});

// GET /api/geojson
router.get('/api/geojson', async (request, env) => {
    try {
        // Fetch the main GeoJSON data from R2
        const geojsonData = await getR2Object(env, 'GEOJSON_BUCKET', GEOJSON_OBJECT_KEY, 'json');

        // Basic validation
        if (!geojsonData || !geojsonData.type || !Array.isArray(geojsonData.features)) {
            console.error("Invalid GeoJSON structure received from R2");
            return error(500, 'Invalid map data format.', { headers: corsHeaders });
        }

        // No processing needed here, just return the fetched data
        return json(geojsonData, { headers: corsHeaders });

    } catch (err) {
        console.error("Error in /api/geojson:", err);
        const status = err.message.includes("not found") ? 404 : 500;
        return error(status, err.message || 'Error retrieving map data.', { headers: corsHeaders });
    }
});

// GET /api/get_index_fields
router.get('/api/get_index_fields', (request, env) => {
    // Directly return the hardcoded list of JS variable names the frontend expects
    // Ensure this list matches the 'valid_index_variables_for_selection' in app.py
     const indexFields = [
        'no_high_school_rate', 'no_car_rate', 'total_no_work_rate',
        'poverty_rate', 'renter_rate', 'total_no_ins_rate', 'sdwalk_length_m',
        'bik_length_m', 'park_area', 'sidewalk_per_cap', 'park_per_cap',
        'bike_per_cap', 'healthy_retailer', 'pharma', 'clinic', 'healthy_ret_cap',
        'pharma_cap', 'clinic_cap', 'PRE1960PCT', 'OZONE', 'PM25', 'PNPL', 'PRMP',
        'PTSDF', 'DSLPM', 'unhealthy_ret_cap', 'liq_tab_cap', 'food_retailer_cap',
        // Add Health Outcomes & Pre-defined if selectable for custom index
        'Obesity', 'Diabetes', 'High Blood Pressure', 'Coronary Heart Disease',
        'High Cholesterol', 'Depression', 'Stroke', 'Annual Checkup', 'Physical Inactivity',
        'ndi', 'uei', 'hoi','andi_final', 'auie_final', 'ahoi_final'// Assuming base names match frontend selection value
    ];

    return json(indexFields, { headers: corsHeaders });
});


// POST /api/generate_residential_index
router.post('/api/generate_residential_index', async (request, env) => {
    try {
        const { name, variables: selectedVarsJS } = await request.json();
        const indexBaseName = cleanIndexName(name);
        const indexColName = `${indexBaseName}_RES`;

        if (!indexBaseName || !selectedVarsJS || !selectedVarsJS.length) {
            return error(400, 'Index name and variables required.', { headers: corsHeaders });
        }
        console.log(`Generating Residential Index: ${indexColName} for variables: ${selectedVarsJS.join(', ')}`);

        // 1. Fetch Base GeoJSON
        const geojsonData = await getR2Object(env, 'GEOJSON_BUCKET', GEOJSON_OBJECT_KEY, 'json');
        if (!geojsonData || !Array.isArray(geojsonData.features)) {
             return error(500, 'Failed to load base map data.', { headers: corsHeaders });
        }

        // 2. *** IMPLEMENT RESIDENTIAL INDEX CALCULATION (Placeholder) ***
        //    - Needs to map `selectedVarsJS` to their corresponding `_zscore_o` column names.
        //    - Check if those `_zscore_o` columns exist in the features' properties.
        //    - Iterate through `geojsonData.features`.
        //    - For each feature, calculate the average of the available/valid `_zscore_o` values for the selected variables.
        //    - Multiply by 100.
        //    - Add the result to `feature.properties[indexColName]`.

        console.warn(`WORKER TODO: Implement actual residential index calculation for ${indexColName}`);
        let columnsUsedCount = 0;
        geojsonData.features.forEach(feature => {
            if (!feature.properties) feature.properties = {};
            // --- Placeholder Calculation ---
            let sum = 0;
            let count = 0;
            selectedVarsJS.forEach(jsVar => {
                // Simulate finding the _zscore_o column based on jsVar
                const zscoreCol = `${jsVar.replace(/ /g, '')}_zscore_o`; 
                if (feature.properties.hasOwnProperty(zscoreCol)) {
                    const val = parseFloat(feature.properties[zscoreCol]);
                    if (!isNaN(val)) {
                        sum += val;
                        count++;
                    }
                }
            });
            const avgZscore = count > 0 ? sum / count : NaN;
            feature.properties[indexColName] = !isNaN(avgZscore) ? avgZscore * 100 : null; // Assign placeholder or null
            if (count > 0) columnsUsedCount++;
             // --- End Placeholder ---
        });
         console.log(`Placeholder calculation done for ${indexColName}. Used columns in ${columnsUsedCount}/${geojsonData.features.length * selectedVarsJS.length} checks.`);
         if (columnsUsedCount === 0) console.warn("No relevant _zscore_o columns found for calculation based on placeholder logic.");

        // 3. Return Modified GeoJSON
        return json(geojsonData, { headers: corsHeaders });

    } catch (err) {
        console.error(`Error generating residential index:`, err);
        const status = err.message.includes("not found") ? 404 : 500;
        return error(status, err.message || 'Failed to generate residential index.', { headers: corsHeaders });
    }
});


// POST /api/generate_index (Activity Index - REVISED TO USE PARQUET VIA DUCKDB-WASM)
router.post('/api/generate_index', async (request, env) => {
    let db = null;
    let connection = null;
    try {
        const { name, variables: selectedVarsJS } = await request.json();
        const indexBaseName = cleanIndexName(name);
        const indexColName = `${indexBaseName}_ACT`;

        if (!indexBaseName || !selectedVarsJS || !selectedVarsJS.length) {
            return error(400, 'Index name and variables required.', { headers: corsHeaders });
        }
        console.log(`Generating Activity Index: ${indexColName} for variables: ${selectedVarsJS.join(', ')}`);

        // 1. Fetch BASE GeoJSON (needed for merging results back)
        const geojsonData = await getR2Object(env, R2_BINDING_NAME, GEOJSON_OBJECT_KEY, 'json');
        if (!geojsonData || !Array.isArray(geojsonData.features)) {
            return error(500, 'Failed to load base map data.', { headers: corsHeaders });
        }

        // 2. Fetch Parquet Data as ArrayBuffer
        console.log("Fetching Parquet data from R2...");
        const parquetBuffer = await getR2Object(env, R2_BINDING_NAME, PARQUET_OBJECT_KEY, 'arrayBuffer');
        if (!parquetBuffer || parquetBuffer.byteLength === 0) {
            return error(500, 'Failed to load Parquet data for activity index.', { headers: corsHeaders });
        }
        console.log(`Parquet data fetched (${(parquetBuffer.byteLength / (1024*1024)).toFixed(2)} MB).`);

        // 3. Initialize DuckDB-WASM
        db = await getDb(env); // Get potentially cached instance
        connection = await db.connect(); // Connect to the database instance

        // 4. Register Parquet Buffer as a virtual file/table
        //    Convert ArrayBuffer to Uint8Array for DuckDB
        const parquetUint8Array = new Uint8Array(parquetBuffer);
        const parquetFileName = `data.parquet`; // Temporary filename in WASM FS
        console.log("Registering Parquet buffer with DuckDB...");
        await db.registerFileBuffer(parquetFileName, parquetUint8Array);
        console.log("Parquet buffer registered.");

        // 5. Construct the SQL Query
        //    Map JS variable names to expected _zscore_d columns in Parquet
        const requiredZscoreDCols = selectedVarsJS.map(jsVar => `${jsVar.replace(/ /g, '')}_zscore_d`); // Adjust mapping if needed
        //    Build the weighted sum expression dynamically
        const weightedSumExprParts = requiredZscoreDCols.map(col => `"${col}"::DOUBLE * "perc_visit"::DOUBLE`);
        const weightedSumSql = weightedSumExprParts.join(' + ');

        if (!weightedSumSql) {
             await closeDbConnection(connection); // Cleanup connection
             return error(400, 'No valid variables selected for index calculation.', { headers: corsHeaders });
        }

        // The SQL query to replicate the Python DuckDB logic
        const query = `
            SELECT
                "Origin_tract"::VARCHAR AS Origin_tract, -- Ensure string type for grouping/joining
                SUM(${weightedSumSql}) AS total_weighted_sum
            FROM read_parquet('${parquetFileName}') -- Query the registered file
            WHERE "perc_visit" IS NOT NULL AND "perc_visit" != 0
            GROUP BY "Origin_tract"
        `;

        console.log("Executing DuckDB query for weighted sums...");
        // console.log("Query:", query); // Optional: Log the query for debugging

        // 6. Execute Query and Fetch Results (using Arrow format)
        const arrowResult = await connection.query(query); // Returns an Arrow Table
        const resultsArray = arrowResult.toArray(); // Convert Arrow Table to array of objects
        console.log(`DuckDB query executed. Received ${resultsArray.length} aggregated results.`);

        // 7. Process Results into a Map for easy lookup
        const calculatedIndexValues = new Map();
        const numVars = selectedVarsJS.length; // Count selected variables

        for (const row of resultsArray) {
            const originTract = row.Origin_tract; // Already cast to VARCHAR in SQL
            const totalSum = row.total_weighted_sum; // DuckDB sum result

            if (originTract != null && totalSum != null && !isNaN(totalSum) && numVars > 0) {
                // Final calculation: SUM[ weight * I_ik ] * 100
                // Assuming _zscore_d columns *are* the I_ik values needed (or used to calculate them)
                // The SQL already sums (zscore * weight). Now multiply sum by 100.
                // Your Python code averaged: (total_sum / num_vars * 100.0)
                // Let's stick to the formula description: Sum(weight * I_ik) * 100
                // If I_ik itself was the average z-score, then the SQL sum is correct.
                // Let's use the formula description: sum * 100
                const finalIndexValue = totalSum * 100;
                calculatedIndexValues.set(originTract.toString().trim(), finalIndexValue);
            } else {
                // console.warn(`Skipping result for Origin ${originTract}: sum=${totalSum}, numVars=${numVars}`);
            }
        }
        console.log(`Processed results into map for ${calculatedIndexValues.size} origin tracts.`);

        // 8. Merge calculated values into the main geojsonData
        let mergeCount = 0;
        geojsonData.features.forEach(feature => {
            if (!feature.properties) feature.properties = {};
            const featureOriginId = feature.properties['Origin_tract']?.toString().trim();
            if (featureOriginId && calculatedIndexValues.has(featureOriginId)) {
                const calcValue = calculatedIndexValues.get(featureOriginId);
                feature.properties[indexColName] = !isNaN(calcValue) ? calcValue : null; // Assign calculated value or null
                mergeCount++;
            } else {
                 // Assign null if no calculated value was found for this origin
                 feature.properties[indexColName] = null;
            }
        });
        console.log(`Merged activity index values into ${mergeCount}/${geojsonData.features.length} features.`);
        if (mergeCount < geojsonData.features.length) {
            console.warn(`Some features in GeoJSON did not have a corresponding calculated activity index value.`);
        }

        // 9. Cleanup DuckDB Connection & File Registration (Important!)
        console.log("Cleaning up DuckDB resources...");
        await closeDbConnection(connection); // Close the connection first
        connection = null; // Nullify to prevent reuse if error occurs later
        // await db.dropFile(parquetFileName); // Remove the virtual file if API exists (check docs)
        // OR simply let the worker instance recycle if file registration is temporary

        // 10. Return Modified GeoJSON
        return json(geojsonData, { headers: corsHeaders });

    } catch (err) {
        console.error(`Error generating activity index using DuckDB:`, err);
        // Attempt to cleanup connection on error too
        if (connection) await closeDbConnection(connection);
        const status = err.message?.includes("not found") ? 404 : (err.status || 500);
        return error(status, err.message || 'Failed to generate activity index.', { headers: corsHeaders });
    } finally {
         // Ensure connection is closed even if errors occur outside main try block
         if (connection) await closeDbConnection(connection);
    }
});


// --- Catch-all for 404s ---
router.all('*', () => new Response('404 Not Found.', { status: 404, headers: corsHeaders }));

// --- NEW Export using onRequest ---
export async function onRequest(context) {
  // context contains request, env, ctx, etc.
  // Extract what you need, particularly request and env
  const { request, env, ctx } = context;

  try {
    // Directly call your itty-router's handler
    return await router.handle(request, env, ctx)
        .catch(err => {
            // Handle errors specifically from the router if necessary
            console.error("Error caught within router.handle:", err);
            // Make sure to return a Response object
            // Use error helper or create Response manually, ensuring CORS
             const status = err.status || 500;
             const message = err.message || "Internal Server Error";
             // Assuming your 'error' utility function from itty-router adds CORS
             // If not, add them manually: return new Response(message, { status, headers: corsHeaders });
             return error(status, message, { headers: corsHeaders }); // Use itty-router's error helper if it includes headers
        });
  } catch (err) {
      // Catch unexpected errors outside the router handling
      console.error("Unhandled exception during request processing:", err);
      return new Response("Internal Server Error", { status: 500, headers: corsHeaders }); // Ensure CORS
  }
}