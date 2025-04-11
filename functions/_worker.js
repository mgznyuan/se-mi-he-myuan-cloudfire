// functions/_worker.js OR functions/api/[[path]].js (depending on your routing setup)

import { Router, error, json } from 'itty-router';
import * as duckdb from '@duckdb/duckdb-wasm';

// --- Configuration ---
const GEOJSON_OBJECT_KEY = 'data_residential.geojson'; // Assumes this contains base geometry + _zscore_o columns
const PARQUET_OBJECT_KEY = 'full_data.parquet';      // Assumes this contains Origin_tract, perc_visit, and _zscore_d columns
const R2_BINDING_NAME_TO_USE = 'GEOJSON_BUCKET';     // MUST match wrangler.toml or Pages binding name

// --- Router Setup ---
const router = Router();

// --- DuckDB WASM Initialization Helper ---
let dbInstance = null;
let dbInitializing = null;

async function getDb(env) {
    if (dbInitializing) {
        console.log("DuckDB-WASM initialization already in progress, waiting...");
        return await dbInitializing;
    }
    if (dbInstance) {
        return dbInstance;
    }

    console.log("Attempting DuckDB-WASM initialization...");
    dbInitializing = (async () => {
        try {
            const JSDELIVR_BUNDLES = duckdb.getJsDelivrBundles();
            const bundle = await duckdb.selectBundle(JSDELIVR_BUNDLES);
            const worker_url = URL.createObjectURL(
                new Blob([`importScripts("${bundle.mainWorker}");`], { type: 'text/javascript' })
            );

            const worker = new Worker(worker_url);
            const logger = new duckdb.ConsoleLogger();
            const db = new duckdb.AsyncDuckDB(logger, worker);

            await db.instantiate(bundle.mainModule, bundle.pthreadWorker);
            URL.revokeObjectURL(worker_url);

            console.log("DuckDB-WASM Initialized Successfully.");
            dbInstance = db;
            return db;
        } catch (err) {
            console.error("DuckDB-WASM Initialization Failed:", err);
            dbInstance = null;
            throw new Error(`Failed to initialize query engine: ${err.message}`);
        } finally {
            dbInitializing = null;
        }
    })();

    return await dbInitializing;
}

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

// --- Helper Functions (cleanIndexName, verifyPasscode, getR2Object, calculateUnderlyingResidentialIndex) ---
// Keep your existing helper functions here - they seem generally correct.
// Make sure verifyPasscode reads `env.PASSCODE_HASH`
// Make sure getR2Object uses R2_BINDING_NAME_TO_USE

/**
 * Cleans a user-provided name... (keep existing implementation)
 */
function cleanIndexName(name) {
    // ... (keep existing implementation) ...
    if (typeof name !== 'string' || !name) {
        return `invalid_name_${Date.now()}`;
    }
    const cleaned = name.trim()
                       .replace(/\s+/g, '_')
                       .replace(/[^\w_]/g, '');
    return cleaned || `invalid_name_${Date.now()}`;
}

/**
 * Securely verifies a provided passcode... (keep existing implementation)
 */
async function verifyPasscode(providedPasscode, storedHash) {
    // ... (keep existing implementation using crypto.subtle.digest) ...
     if (!providedPasscode || typeof providedPasscode !== 'string' || !storedHash || typeof storedHash !== 'string') {
        console.error("verifyPasscode: Invalid input provided.");
        return false;
    }
    storedHash = storedHash.toLowerCase();
    try {
        const encoder = new TextEncoder();
        const data = encoder.encode(providedPasscode);
        const hashBuffer = await crypto.subtle.digest('SHA-256', data);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        const calculatedHashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
        if (calculatedHashHex === storedHash) {
            return true;
        } else {
            console.log("Passcode verification failed: Hashes do not match.");
            return false;
        }
    } catch (error) {
        console.error("Error during passcode hash verification:", error);
        return false;
    }
}

/**
 * Fetches an object from an R2 bucket binding... (keep existing implementation)
 */
async function getR2Object(env, bindingName, objectKey, responseType = 'json') {
    // ... (keep existing implementation checking env[bindingName], object === null, parsing) ...
     const bucket = env[bindingName];
    if (!bucket) {
        const errorMsg = `R2 bucket binding '${bindingName}' not configured in Worker environment.`;
        console.error(errorMsg);
        throw new Error(errorMsg);
    }
    const object = await bucket.get(objectKey);
    if (object === null) {
        const errorMsg = `Required data file '${objectKey}' not found in R2 bucket bound to '${bindingName}'.`;
        console.error(errorMsg);
        const err = new Error(errorMsg);
        err.status = 404;
        throw err;
    }
     try {
        switch (responseType) {
            case 'json': return await object.json();
            case 'text': return await object.text();
            case 'arrayBuffer': return await object.arrayBuffer();
            case 'blob': return await object.blob();
            case 'stream': return object.body;
            default:
                console.warn(`Unsupported responseType '${responseType}' requested for R2 object '${objectKey}'. Returning raw R2Object.`);
                return object;
        }
    } catch (e) {
        const errorMsg = `Failed to parse R2 object '${objectKey}' (binding '${bindingName}') as ${responseType}: ${e.message}`;
        console.error(errorMsg, e);
        throw new Error(errorMsg);
    }
}

/**
 * Calculates the underlying residential index for a given feature... (keep existing implementation)
 */
function calculateUnderlyingResidentialIndex(feature, selectedVarsJS) {
    // ... (keep existing implementation looping selectedVarsJS, mapping to _zscore_o, summing, averaging, * 100) ...
     if (!feature?.properties || !Array.isArray(selectedVarsJS) || selectedVarsJS.length === 0) {
        return null;
    }
    let zscoreSum = 0;
    let zscoreCount = 0;
    selectedVarsJS.forEach(jsVar => {
        // *** Verify this mapping: jsVar (e.g., 'poverty_rate') maps to 'poverty_rate_zscore_o' ***
        const zscoreColName = `${jsVar.replace(/ /g, '')}_zscore_o`;
        if (feature.properties.hasOwnProperty(zscoreColName)) {
            const value = parseFloat(feature.properties[zscoreColName]);
            if (!isNaN(value)) {
                zscoreSum += value;
                zscoreCount++;
            }
        }
    });
    if (zscoreCount > 0) {
        const averageZscore = zscoreSum / zscoreCount;
        return averageZscore * 100;
    } else {
        return null;
    }
}


// --- NEW CORS Middleware ---
const handleCors = (request, env) => {
    const origin = request.headers.get('Origin');
    // Define allowed origins (use environment variable in production)
    // Example: set ALLOWED_ORIGINS="https://your-project.pages.dev,http://localhost:8788"
    const allowedOrigins = env.ALLOWED_ORIGINS ? env.ALLOWED_ORIGINS.split(',') : ['*']; // Default to wildcard if not set

    let headers = {
        'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization', // Allow Content-Type for POST
        'Access-Control-Max-Age': '86400', // Cache preflight for 1 day
    };

    // Dynamically set Allow-Origin
    if (origin && allowedOrigins.includes(origin)) {
        headers['Access-Control-Allow-Origin'] = origin;
    } else if (allowedOrigins.includes('*')) {
        // Allow '*' only if explicitly configured or as default
        headers['Access-Control-Allow-Origin'] = '*';
    } else {
        // Origin not allowed, don't add the header (browser will block)
        // Or return an error response immediately:
        // return new Response('CORS Origin Not Allowed', { status: 403 });
    }

    // Handle Preflight (OPTIONS) requests
    if (request.method === 'OPTIONS') {
        return new Response(null, { headers });
    }

    // Attach CORS headers to the request object for downstream use
    // This assumes itty-router passes the request object through.
    // A more robust way might be to wrap the final response.
    request.corsHeaders = headers;
};

// Apply CORS middleware to all requests *before* routing
router.all('*', handleCors);

// --- API Routes ---

// POST /api/login
router.post('/api/login', async (request, env) => {
    try {
        const { passcode } = await request.json();
        const storedHash = env.PASSCODE_HASH; // Ensure this secret is set!

        if (!storedHash) {
            console.error("Critical: PASSCODE_HASH secret not set in Worker environment.");
            return error(500, 'Server configuration error.', { headers: request.corsHeaders }); // Use headers from middleware
        }

        const isValid = await verifyPasscode(passcode, storedHash);

        if (isValid) {
            return json({ success: true }, { headers: request.corsHeaders });
        } else {
            return new Response(JSON.stringify({ success: false, error: 'Invalid passcode.' }), {
                status: 401, // Unauthorized
                headers: { ...request.corsHeaders, 'Content-Type': 'application/json' }
            });
        }
    } catch (err) {
        console.error("Login error:", err);
        return new Response(JSON.stringify({ success: false, error: 'Server error during login.' }), {
            status: 500,
            headers: { ...request.corsHeaders, 'Content-Type': 'application/json' }
        });
    }
});

// GET /api/geojson
router.get('/api/geojson', async (request, env) => {
    try {
        const geojsonData = await getR2Object(env, R2_BINDING_NAME_TO_USE, GEOJSON_OBJECT_KEY, 'json');
        if (!geojsonData || !geojsonData.type || !Array.isArray(geojsonData.features)) {
            console.error("Invalid GeoJSON structure received from R2");
            return error(500, 'Invalid map data format.', { headers: request.corsHeaders });
        }
        return json(geojsonData, { headers: request.corsHeaders });
    } catch (err) {
        console.error("Error in /api/geojson:", err);
        const status = err.message.includes("not found") ? 404 : 500;
        return error(status, err.message || 'Error retrieving map data.', { headers: request.corsHeaders });
    }
});

// GET /api/get_index_fields
router.get('/api/get_index_fields', (request, env) => {
    // *** CRITICAL VERIFICATION NEEDED ***
    // Ensure this list EXACTLY matches:
    // 1. The `value` attributes in your frontend multi-select <option> tags.
    // 2. The base names needed to construct column names (e.g., 'poverty_rate' -> 'poverty_rate_zscore_o' / 'poverty_rate_zscore_d')
     const indexFields = [
        'no_high_school_rate', 'no_car_rate', 'total_no_work_rate',
        'poverty_rate', 'renter_rate', 'total_no_ins_rate', 'sdwalk_length_m',
        'bik_length_m', 'park_area', 'sidewalk_per_cap', 'park_per_cap',
        'bike_per_cap', 'healthy_retailer', 'pharma', 'clinic', 'healthy_ret_cap',
        'pharma_cap', 'clinic_cap', 'PRE1960PCT', 'OZONE', 'PM25', 'PNPL', 'PRMP',
        'PTSDF', 'DSLPM', 'unhealthy_ret_cap', 'liq_tab_cap', 'food_retailer_cap',
        'Obesity', 'Diabetes', 'High Blood Pressure', 'Coronary Heart Disease',
        'High Cholesterol', 'Depression', 'Stroke', 'Annual Checkup', 'Physical Inactivity',
        'ndi', 'uei', 'hoi',
        'andi_final', 'auie_final', 'ahoi_final' // Verify if these are selectable for *custom* index generation
    ];
    console.log("Returning index fields:", indexFields); // Log for verification
    return json(indexFields, { headers: request.corsHeaders });
});


// POST /api/generate_residential_index
router.post('/api/generate_residential_index', async (request, env) => {
    try {
        const { name, variables: selectedVarsJS } = await request.json();
        const indexBaseName = cleanIndexName(name);
        const indexColName = `${indexBaseName}_RES`;

        if (!indexBaseName || !selectedVarsJS || !selectedVarsJS.length) {
            return error(400, 'Index name and variables required.', { headers: request.corsHeaders });
        }
        console.log(`Generating Residential Index: ${indexColName} for variables: ${selectedVarsJS.join(', ')}`);

        // 1. Fetch Base GeoJSON
        const geojsonData = await getR2Object(env, R2_BINDING_NAME_TO_USE, GEOJSON_OBJECT_KEY, 'json');
        if (!geojsonData || !Array.isArray(geojsonData.features)) {
            return error(500, 'Failed to load base map data.', { headers: request.corsHeaders });
        }

        // 2. *** Calculate Residential Index using the helper function ***
        let calculationCount = 0;
        geojsonData.features.forEach(feature => {
            if (!feature.properties) feature.properties = {}; // Ensure properties object exists

            // Call the helper function to calculate the index for this feature
            const indexValue = calculateUnderlyingResidentialIndex(feature, selectedVarsJS);

            // Assign the calculated value (or null if calculation failed)
            feature.properties[indexColName] = indexValue;
            if (indexValue !== null) calculationCount++;
        });
        console.log(`Calculated residential index for ${calculationCount}/${geojsonData.features.length} features as ${indexColName}.`);
         if (calculationCount === 0 && geojsonData.features.length > 0) {
             console.warn("Residential index calculation resulted in null for all features. Check if GeoJSON contains required '_zscore_o' columns for selected variables.");
         }

        // 3. Return Modified GeoJSON
        return json(geojsonData, { headers: request.corsHeaders });

    } catch (err) {
        console.error(`Error generating residential index:`, err);
        const status = err.message.includes("not found") ? 404 : 500;
        return error(status, err.message || 'Failed to generate residential index.', { headers: request.corsHeaders });
    }
});


// POST /api/generate_index (Activity Index - Using DuckDB)
router.post('/api/generate_index', async (request, env) => {
    let db = null;
    let connection = null;
    const parquetFileName = `data.parquet`; // Define here for use in finally block if needed

    try {
        const { name, variables: selectedVarsJS } = await request.json();
        const indexBaseName = cleanIndexName(name);
        const indexColName = `${indexBaseName}_ACT`;

        if (!indexBaseName || !selectedVarsJS || !selectedVarsJS.length) {
            return error(400, 'Index name and variables required.', { headers: request.corsHeaders });
        }
        console.log(`Generating Activity Index: ${indexColName} for variables: ${selectedVarsJS.join(', ')}`);

        // 1. Fetch BASE GeoJSON (needed for merging results back)
        const geojsonData = await getR2Object(env, R2_BINDING_NAME_TO_USE, GEOJSON_OBJECT_KEY, 'json');
        if (!geojsonData || !Array.isArray(geojsonData.features)) {
            return error(500, 'Failed to load base map data.', { headers: request.corsHeaders });
        }

        // 2. Fetch Parquet Data as ArrayBuffer
        const parquetBuffer = await getR2Object(env, R2_BINDING_NAME_TO_USE, PARQUET_OBJECT_KEY, 'arrayBuffer');
        if (!parquetBuffer || parquetBuffer.byteLength === 0) {
            return error(500, 'Failed to load Parquet data for activity index.', { headers: request.corsHeaders });
        }

        // 3. Initialize DuckDB-WASM & Connect
        db = await getDb(env);
        connection = await db.connect();

        // 4. Register Parquet Buffer
        const parquetUint8Array = new Uint8Array(parquetBuffer);
        await db.registerFileBuffer(parquetFileName, parquetUint8Array);
        console.log("Parquet buffer registered with DuckDB as", parquetFileName);

        // 5. Construct the SQL Query
        // *** CRITICAL VERIFICATION NEEDED for column names ***
        const requiredZscoreDCols = selectedVarsJS.map(jsVar => `${jsVar.replace(/ /g, '')}_zscore_d`); // e.g., 'poverty_rate_zscore_d'
        const weightCol = `"perc_visit"`; // Verify this column name in Parquet
        const originCol = `"Origin_tract"`; // Verify this column name in Parquet

        // Filter out variables that might not have a corresponding _zscore_d column (optional but safer)
        // This requires knowing the actual Parquet schema, which we don't have here. Assuming all exist for now.
        const weightedSumExprParts = requiredZscoreDCols.map(col => `"${col}"::DOUBLE * ${weightCol}::DOUBLE`);

        if (weightedSumExprParts.length === 0) {
            await closeDbConnection(connection); connection = null;
            return error(400, 'No valid variables selected or mapping failed.', { headers: request.corsHeaders });
        }
        const weightedSumSql = weightedSumExprParts.join(' + ');

        const query = `
            SELECT
                ${originCol}::VARCHAR AS Origin_tract, -- Ensure string type
                SUM(${weightedSumSql}) AS total_weighted_sum
            FROM read_parquet('${parquetFileName}')
            WHERE ${weightCol} IS NOT NULL AND ${weightCol} != 0 -- Filter invalid weights
            GROUP BY ${originCol}
        `;
        console.log("Executing DuckDB query for activity index...");

        // 6. Execute Query and Fetch Results
        const arrowResult = await connection.query(query);
        const resultsArray = arrowResult.toArray();
        console.log(`DuckDB query finished. Received ${resultsArray.length} results.`);

        // 7. Process Results into a Map
        const calculatedIndexValues = new Map();
        for (const row of resultsArray) {
            const originTract = row.Origin_tract;
            const totalSum = row.total_weighted_sum;

            if (originTract != null && totalSum != null && !isNaN(totalSum)) {
                // *** VERIFY FINAL CALCULATION ***
                // Formula seems to be Sum(weight * I_ik) * 100, where I_ik are the zscore_d values.
                // The SQL calculates Sum(weight * zscore_d). So multiply the result by 100.
                const finalIndexValue = totalSum * 100;
                calculatedIndexValues.set(originTract.toString().trim(), finalIndexValue);
            }
        }
        console.log(`Processed results into map for ${calculatedIndexValues.size} origin tracts.`);

        // 8. Merge calculated values into the main geojsonData
        let mergeCount = 0;
        geojsonData.features.forEach(feature => {
            if (!feature.properties) feature.properties = {};
            const featureOriginId = feature.properties['Origin_tract']?.toString().trim(); // Match lookup format
            if (featureOriginId && calculatedIndexValues.has(featureOriginId)) {
                feature.properties[indexColName] = calculatedIndexValues.get(featureOriginId);
                mergeCount++;
            } else {
                feature.properties[indexColName] = null; // Assign null if no calculation result
            }
        });
        console.log(`Merged activity index values into ${mergeCount}/${geojsonData.features.length} features as ${indexColName}.`);

        // 9. Cleanup DuckDB Connection (File buffer should detach on connection close/worker end)
        await closeDbConnection(connection);
        connection = null; // Prevent reuse in finally block if already closed
        console.log("DuckDB connection closed.");

        // 10. Return Modified GeoJSON
        return json(geojsonData, { headers: request.corsHeaders });

    } catch (err) {
        console.error(`Error generating activity index using DuckDB:`, err);
        const status = err.message?.includes("not found") ? 404 : (err.status || 500);
        return error(status, err.message || 'Failed to generate activity index.', { headers: request.corsHeaders });
    } finally {
        // Ensure connection is closed if something went wrong after opening it
        if (connection) {
            console.log("Closing DuckDB connection in finally block.");
            await closeDbConnection(connection);
        }
        // Optionally try to drop the file buffer if the API exists and is needed
        // if (db && typeof db.dropFile === 'function') {
        //    try { await db.dropFile(parquetFileName); } catch(e){ console.error("Error dropping file buffer:", e)}
        // }
    }
});


// --- Catch-all for 404s ---
// Ensure this comes *after* all other routes
router.all('*', (request) => {
     // Use the headers from the CORS middleware if available
    const headers = request.corsHeaders || { 'Content-Type': 'application/json' };
    return new Response(JSON.stringify({ error: 'Not Found' }), { status: 404, headers });
});

// --- Main Export for Cloudflare Pages Functions ---
export async function onRequest(context) {
    // context includes: request, env, params, waitUntil, next, data
    const { request, env, ctx } = context; // Use ctx for waitUntil if needed

    try {
        // Add a default CORS header object in case CORS middleware fails early
        request.corsHeaders = request.corsHeaders || { 'Access-Control-Allow-Origin': '*' }; // Basic fallback

        // Handle the request with the router
        const response = await router.handle(request, env, ctx);

        // *** IMPORTANT: Apply CORS headers to the FINAL response ***
        // The middleware only attached them to the *request*. We need them on the *response*.
        const finalHeaders = new Headers(response.headers); // Clone existing headers
        Object.entries(request.corsHeaders).forEach(([key, value]) => {
            finalHeaders.set(key, value);
        });

        // Ensure Content-Type if missing (optional, depends on router responses)
        if (!finalHeaders.has('Content-Type') && response.status !== 204 && response.status !== 304) {
             finalHeaders.set('Content-Type', 'application/json'); // Default assumption
        }

        // Return the response with combined headers
        return new Response(response.body, {
            status: response.status,
            statusText: response.statusText,
            headers: finalHeaders
        });

    } catch (err) {
        // Catch unexpected errors (outside router handling)
        console.error("Unhandled exception during request processing:", err);
        // Ensure CORS headers on critical error responses too
        const errorHeaders = request.corsHeaders || { 'Access-Control-Allow-Origin': '*' };
        errorHeaders['Content-Type'] = 'application/json';
        return new Response(JSON.stringify({ error: 'Internal Server Error' }), {
            status: 500,
            headers: errorHeaders
        });
    }
}