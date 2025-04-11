// functions/_worker.js OR functions/api/[[path]].js (depending on your routing setup)

import { Router, error, json } from 'itty-router';
import { tableFromIPC, RecordBatchStreamReader } from 'apache-arrow'; // <<< --- ADDED: Verify exact Arrow imports needed
import bcrypt from 'bcryptjs'; 
// --- Configuration ---
const GEOJSON_OBJECT_KEY = 'data_residential.geojson'; // Base geometry + _zscore_o columns
const PARQUET_OBJECT_KEY = 'full_data.parquet';      // Origin_tract, perc_visit, + _zscore_d columns
const R2_BINDING_NAME_TO_USE = 'GEOJSON_BUCKET';     // MUST match wrangler.toml or Pages binding name

// --- Router Setup ---
const router = Router();

// --- Helper Functions ---

function cleanIndexName(name) {
     if (typeof name !== 'string' || !name) {
        return `invalid_name_${Date.now()}`;
    }
    // Limit length to prevent excessively long column names if needed
    const cleaned = name.trim()
                       .replace(/\s+/g, '_')       // Replace whitespace with underscore
                       .replace(/[^\w_]/g, '')    // Remove non-alphanumeric/underscore chars
                       .substring(0, 50);        // Limit length (e.g., 50 chars)
    // Ensure it doesn't start with a number or is empty after cleaning
    return /^[a-zA-Z_]/.test(cleaned) ? cleaned : `idx_${cleaned || Date.now()}`;
}

/**
 * Securely verifies a provided passcode against a stored bcrypt hash.
 * REQUIRES a bundled bcrypt library (like bcryptjs).
 * @param {string} providedPasscode - The passcode attempt from the user.
 * @param {string} storedBcryptHash - The securely stored bcrypt hash from secrets.
 * @returns {Promise<boolean>} - True if the passcode matches the hash, false otherwise.
 */
async function verifyPasscode(providedPasscode, storedBcryptHash) {
    // <<< --- SECURITY FIX: Replaced insecure SHA256 with bcrypt --- >>>
    if (!providedPasscode || typeof providedPasscode !== 'string' || !storedBcryptHash || typeof storedBcryptHash !== 'string') {
        console.error("verifyPasscode: Invalid input provided.");
        return false;
    }
    // Ensure bcryptjs is available/imported correctly
    // This relies on you importing and bundling 'bcryptjs'
    if (typeof bcrypt === 'undefined' || typeof bcrypt.compare !== 'function') {
         console.error("CRITICAL: bcrypt library (e.g., bcryptjs) is not available or not imported correctly for passcode verification.");
         // Consider throwing an error here instead? Depends on desired failure mode.
         return false; // Fail securely
    }

    try {
        // bcrypt.compare securely handles the salt embedded in the stored hash
        const isMatch = await bcrypt.compare(providedPasscode, storedBcryptHash);
        if (!isMatch) {
             // Avoid logging failure reasons that might help attackers (e.g., timing differences)
             console.log("Passcode verification failed.");
        }
        return isMatch;
    } catch (error) {
        // Log bcrypt errors, but don't expose details to the client
        console.error("Error during bcrypt passcode verification:", error);
        return false; // Return false on any bcrypt error
    }
}

async function getR2Object(env, bindingName, objectKey, responseType = 'json') {
    const bucket = env[bindingName];
    if (!bucket) {
        const errorMsg = `R2 bucket binding '${bindingName}' not configured in Worker environment. Check Pages settings or wrangler.toml.`;
        console.error(errorMsg);
        throw new Error(errorMsg); // Throw error to be caught upstream
    }

    const object = await bucket.get(objectKey);

    if (object === null) {
        const errorMsg = `Required data file '${objectKey}' not found in R2 bucket bound to '${bindingName}'. Ensure file exists in the bucket.`;
        console.error(errorMsg);
        const err = new Error(errorMsg);
        err.status = 404; // Set status for upstream handler
        throw err;
    }

     try {
        switch (responseType) {
            case 'json': return await object.json();
            case 'text': return await object.text();
            case 'arrayBuffer': return await object.arrayBuffer();
            case 'blob': return await object.blob(); // Note: Blob might not be ideal in Worker, ArrayBuffer often better
            case 'stream': return object.body; // ReadableStream
            default:
                 const warnMsg = `Unsupported responseType '${responseType}' requested for R2 object '${objectKey}'.`;
                 console.warn(warnMsg);
                 throw new Error(warnMsg); // Throw error for unsupported types
        }
    } catch (e) {
        // Catch JSON parsing errors etc.
        const errorMsg = `Failed to parse R2 object '${objectKey}' (binding '${bindingName}') as ${responseType}: ${e.message}`;
        console.error(errorMsg, e);
        throw new Error(errorMsg); // Throw error
    }
}

/**
 * Calculates the underlying residential index for a given feature based on selected variables.
 * Assumes variables map to '_zscore_o' columns in feature properties.
 */
function calculateUnderlyingResidentialIndex(feature, selectedVarsJS) {
    if (!feature?.properties || !Array.isArray(selectedVarsJS) || selectedVarsJS.length === 0) {
        return null; // Return null for invalid input or missing properties
    }

    let zscoreSum = 0;
    let zscoreCount = 0;

    selectedVarsJS.forEach(jsVar => {
        // *** CRITICAL VERIFICATION NEEDED: Verify this naming convention is correct ***
        // Assumes frontend variable 'poverty_rate' maps to GeoJSON property 'poverty_rate_zscore_o'
        const zscoreColName = `${jsVar.replace(/ /g, '')}_zscore_o`;

        if (feature.properties.hasOwnProperty(zscoreColName)) {
            const value = parseFloat(feature.properties[zscoreColName]);
            if (!isNaN(value)) {
                zscoreSum += value;
                zscoreCount++;
            } else {
                 // console.warn(`Property '${zscoreColName}' for tract ${feature.properties['Origin_tract']} is not a number.`);
            }
        } else {
             // console.warn(`Required property '${zscoreColName}' missing for tract ${feature.properties['Origin_tract']}.`);
        }
    });

    if (zscoreCount > 0) {
        const averageZscore = zscoreSum / zscoreCount;
        // Multiply by 100 as per original intent? Verify calculation.
        return averageZscore * 100;
    } else {
        // Return null if no valid variables were found/summed for this feature
        return null;
    }
}

// --- CORS Middleware ---
const handleCors = (request, env) => {
    const origin = request.headers.get('Origin');
    // Use environment variable for allowed origins in production
    const allowedOriginsEnv = env.ALLOWED_ORIGINS || ""; // Default to empty string if not set
    // Allow localhost for development if explicitly added or if env var is missing/empty
    const defaultDevOrigin = "http://127.0.0.1:8788"; // Adjust port if needed via wrangler.toml or CLI arg
    const allowedOrigins = allowedOriginsEnv ? allowedOriginsEnv.split(',').map(o => o.trim()) : [defaultDevOrigin];

    // Include localhost if running wrangler dev and env var isn't set to block it
    if (!allowedOriginsEnv && origin && origin.startsWith('http://localhost:')) {
         allowedOrigins.push(origin); // Allow dynamic localhost ports
    }
     if (!allowedOriginsEnv && origin === defaultDevOrigin){
          if (!allowedOrigins.includes(defaultDevOrigin)) allowedOrigins.push(defaultDevOrigin);
     }


    let headers = {
        'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization', // Allow Content-Type, potentially Authorization later
        'Access-Control-Max-Age': '86400', // Cache preflight for 1 day
    };

    // Set Allow-Origin header dynamically and carefully
    if (origin && allowedOrigins.includes(origin)) {
        headers['Access-Control-Allow-Origin'] = origin;
        headers['Vary'] = 'Origin'; // Important for caching when origin varies
    } else {
        // If origin is not in the allowed list, DO NOT send Allow-Origin header.
        // The browser will enforce the block. Sending a fixed '*' can be insecure.
         if (origin) { // Only log if an origin was actually present
            console.warn(`CORS: Origin '${origin}' not in allowed list: [${allowedOrigins.join(', ')}]`);
         }
    }

    // Handle Preflight (OPTIONS) requests immediately
    if (request.method === 'OPTIONS') {
        // Respond only with CORS headers if origin was allowed
        if (headers['Access-Control-Allow-Origin']) {
             return new Response(null, { headers });
        } else {
             // Origin not allowed, return empty 403 or similar
             return new Response('CORS Origin Not Allowed', { status: 403 });
        }
    }

    // Attach determined CORS headers to the request context for the final response
    request.corsHeaders = headers;
};


// Apply CORS middleware *before* routing
router.all('*', handleCors);


// --- API Routes ---

// POST /api/login
router.post('/api/login', async (request, env) => {
    // Ensure response headers are ready even if CORS prevented Allow-Origin header earlier
    const responseHeaders = { ...(request.corsHeaders || {}), 'Content-Type': 'application/json' };

    try {
        let passcode;
        try {
             const data = await request.json();
             passcode = data?.passcode;
        } catch (e) {
            return new Response(JSON.stringify({ success: false, error: 'Invalid JSON request body.' }), {
                status: 400, headers: responseHeaders
            });
        }

        // <<< --- SECURITY CRITICAL: Ensure PASSCODE_HASH secret contains a BCRYPT HASH --- >>>
        const storedHash = env.PASSCODE_HASH;

        if (!storedHash) {
            console.error("CRITICAL: PASSCODE_HASH secret not set or empty in Worker environment.");
            return new Response(JSON.stringify({ success: false, error: 'Server configuration error.' }), {
                status: 500, headers: responseHeaders
            });
        }

        if (!passcode || typeof passcode !== 'string') {
             return new Response(JSON.stringify({ success: false, error: 'Passcode required.' }), {
                status: 400, headers: responseHeaders
            });
        }

        // Use the secure bcrypt verification function
        const isValid = await verifyPasscode(passcode, storedHash);

        if (isValid) {
            // Consider setting a secure, HttpOnly cookie or session token here instead of just success=true
            console.log("Login successful.");
            return new Response(JSON.stringify({ success: true }), {
                status: 200, headers: responseHeaders
            });
        } else {
            // Do not reveal if the user exists, just that login failed
            console.log("Login failed: Invalid passcode.");
            return new Response(JSON.stringify({ success: false, error: 'Invalid passcode.' }), {
                status: 401, // Unauthorized
                headers: responseHeaders
            });
        }
    } catch (err) {
        // Catch unexpected issues
        console.error("Login error:", err);
        return new Response(JSON.stringify({ success: false, error: 'Server error during login.' }), {
            status: 500, headers: responseHeaders
        });
    }
});

// GET /api/geojson
router.get('/api/geojson', async (request, env) => {
    const responseHeaders = { ...(request.corsHeaders || {}), 'Content-Type': 'application/geo+json' }; // Correct Content-Type
    try {
        const geojsonData = await getR2Object(env, R2_BINDING_NAME_TO_USE, GEOJSON_OBJECT_KEY, 'json');
        // Basic validation of GeoJSON structure
        if (!geojsonData || geojsonData.type !== 'FeatureCollection' || !Array.isArray(geojsonData.features)) {
            console.error("Invalid or incomplete GeoJSON structure received from R2:", GEOJSON_OBJECT_KEY);
            return new Response(JSON.stringify({ error: 'Invalid map data format received.' }), {
                status: 500, headers: { ...responseHeaders, 'Content-Type': 'application/json' } // Error is JSON
            });
        }
        return new Response(JSON.stringify(geojsonData), { // Ensure stringify for Response body
            status: 200, headers: responseHeaders
        });
    } catch (err) {
        console.error("Error in /api/geojson:", err);
        const status = err.status || 500; // Use status from error if set (e.g., 404 from getR2Object)
        return new Response(JSON.stringify({ error: err.message || 'Error retrieving map data.' }), {
             status: status, headers: { ...responseHeaders, 'Content-Type': 'application/json' } // Error is JSON
        });
    }
});

// GET /api/get_index_fields
router.get('/api/get_index_fields', (request, env) => {
    const responseHeaders = { ...(request.corsHeaders || {}), 'Content-Type': 'application/json' };
    // *** CRITICAL VERIFICATION NEEDED ***
    // This list MUST EXACTLY match:
    // 1. The `value` attributes in your frontend multi-select <option> tags.
    // 2. The base names used to construct column names for calculations
    //    (e.g., 'poverty_rate' used to find 'poverty_rate_zscore_o' in GeoJSON
    //     and 'poverty_rate_zscore_d' in Parquet).
    // Remove any fields NOT intended for custom index selection.
     const indexFields = [
        'no_high_school_rate', 'no_car_rate', 'total_no_work_rate',
        'poverty_rate', 'renter_rate', 'total_no_ins_rate', 'sdwalk_length_m',
        'bik_length_m', 'park_area', 'sidewalk_per_cap', 'park_per_cap',
        'bike_per_cap', 'healthy_retailer', 'pharma', 'clinic', 'healthy_ret_cap',
        'pharma_cap', 'clinic_cap', 'PRE1960PCT', 'OZONE', 'PM25', 'PNPL', 'PRMP',
        'PTSDF', 'DSLPM', 'unhealthy_ret_cap', 'liq_tab_cap', 'food_retailer_cap',
        // Verify if Health Outcomes are Z-scored and available for index calculation
        // 'Obesity', 'Diabetes', 'High Blood Pressure', 'Coronary Heart Disease',
        // 'High Cholesterol', 'Depression', 'Stroke', 'Annual Checkup', 'Physical Inactivity',
        // Verify if pre-defined indices should be selectable components for *new* custom indices
        'ndi', 'uei', 'hoi',
        // 'andi_final', 'auie_final', 'ahoi_final' // Likely NOT selectable for custom index
    ];
    console.log("Returning index fields:", indexFields);
    // Use itty-router's json helper which handles stringify and content-type
    return json(indexFields, { headers: request.corsHeaders });
});


// POST /api/generate_residential_index
router.post('/api/generate_residential_index', async (request, env) => {
    const responseHeaders = { ...(request.corsHeaders || {}), 'Content-Type': 'application/geo+json' }; // Result is GeoJSON
    try {
        let name, selectedVarsJS;
         try {
             const data = await request.json();
             name = data?.name;
             selectedVarsJS = data?.variables;
        } catch (e) {
            return new Response(JSON.stringify({ error: 'Invalid JSON request body.' }), {
                status: 400, headers: { ...responseHeaders, 'Content-Type': 'application/json' } // Error is JSON
            });
        }

        const indexBaseName = cleanIndexName(name); // Clean the user-provided name
        const indexColName = `${indexBaseName}_RES`; // Construct the final column name

        if (!indexBaseName || !selectedVarsJS || !Array.isArray(selectedVarsJS) || selectedVarsJS.length === 0) {
             return new Response(JSON.stringify({ error: 'Index name and at least one variable are required.' }), {
                status: 400, headers: { ...responseHeaders, 'Content-Type': 'application/json' } // Error is JSON
            });
        }
        console.log(`Generating Residential Index: ${indexColName} for variables: ${selectedVarsJS.join(', ')}`);

        // 1. Fetch Base GeoJSON
        const geojsonData = await getR2Object(env, R2_BINDING_NAME_TO_USE, GEOJSON_OBJECT_KEY, 'json');
        if (!geojsonData || geojsonData.type !== 'FeatureCollection' || !Array.isArray(geojsonData.features)) {
             return new Response(JSON.stringify({ error: 'Invalid base map data format.' }), {
                status: 500, headers: { ...responseHeaders, 'Content-Type': 'application/json' } // Error is JSON
            });
        }

        // 2. Calculate Residential Index for each feature
        let calculationCount = 0;
        let featuresProcessed = 0;
        geojsonData.features.forEach(feature => {
            featuresProcessed++;
            // Ensure properties object exists (safer)
            if (!feature.properties) feature.properties = {};

            const indexValue = calculateUnderlyingResidentialIndex(feature, selectedVarsJS);
            feature.properties[indexColName] = indexValue; // Assign calculated value (can be null)
            if (indexValue !== null) calculationCount++;
        });

        console.log(`Calculated residential index for ${calculationCount} / ${featuresProcessed} features as ${indexColName}.`);
        if (featuresProcessed > 0 && calculationCount === 0) {
             console.warn(`WARNING: Residential index calculation resulted in null for ALL features for index '${indexColName}'. Check required '_zscore_o' columns for [${selectedVarsJS.join(', ')}] in GeoJSON (${GEOJSON_OBJECT_KEY}).`);
        }

        // 3. Return Modified GeoJSON
        return new Response(JSON.stringify(geojsonData), {
            status: 200, headers: responseHeaders
        });

    } catch (err) {
        console.error(`Error generating residential index:`, err);
        const status = err.status || 500;
        return new Response(JSON.stringify({ error: err.message || 'Failed to generate residential index.' }), {
             status: status, headers: { ...responseHeaders, 'Content-Type': 'application/json' } // Error is JSON
        });
    }
});


// POST /api/generate_index (Activity Index - Using Apache Arrow)
router.post('/api/generate_index', async (request, env) => {
    const responseHeaders = { ...(request.corsHeaders || {}), 'Content-Type': 'application/geo+json' }; // Result is GeoJSON

    try {
         let name, selectedVarsJS;
         try {
             const data = await request.json();
             name = data?.name;
             selectedVarsJS = data?.variables;
        } catch (e) {
            return new Response(JSON.stringify({ error: 'Invalid JSON request body.' }), {
                status: 400, headers: { ...responseHeaders, 'Content-Type': 'application/json' } // Error is JSON
            });
        }

        const indexBaseName = cleanIndexName(name);
        const indexColName = `${indexBaseName}_ACT`;

        if (!indexBaseName || !selectedVarsJS || !Array.isArray(selectedVarsJS) || selectedVarsJS.length === 0) {
             return new Response(JSON.stringify({ error: 'Index name and at least one variable are required.' }), {
                status: 400, headers: { ...responseHeaders, 'Content-Type': 'application/json' } // Error is JSON
            });
        }
        console.log(`Generating Activity Index (Arrow): ${indexColName} for variables: ${selectedVarsJS.join(', ')}`);

        // 1. Fetch BASE GeoJSON (needed for merging results back)
        const geojsonData = await getR2Object(env, R2_BINDING_NAME_TO_USE, GEOJSON_OBJECT_KEY, 'json');
        if (!geojsonData || geojsonData.type !== 'FeatureCollection' || !Array.isArray(geojsonData.features)) {
             return new Response(JSON.stringify({ error: 'Invalid base map data format.' }), {
                status: 500, headers: { ...responseHeaders, 'Content-Type': 'application/json' } // Error is JSON
            });
        }

        // 2. Fetch Parquet Data as ArrayBuffer
        console.log(`Fetching Parquet data from R2: ${PARQUET_OBJECT_KEY}`);
        const parquetBuffer = await getR2Object(env, R2_BINDING_NAME_TO_USE, PARQUET_OBJECT_KEY, 'arrayBuffer');
        if (!parquetBuffer || parquetBuffer.byteLength === 0) {
             return new Response(JSON.stringify({ error: 'Failed to load required Parquet data for activity index.' }), {
                status: 500, headers: { ...responseHeaders, 'Content-Type': 'application/json' } // Error is JSON
            });
        }
        console.log(`Parquet data fetched successfully (${parquetBuffer.byteLength} bytes).`);
        const parquetUint8Array = new Uint8Array(parquetBuffer);

        // 3. Read Parquet data using Apache Arrow JS
        // *** ACTION REQUIRED: Verify the correct Arrow JS API for reading Parquet from a buffer ***
        // This is a plausible approach using RecordBatchStreamReader, but double-check Arrow JS docs.
        console.log("Attempting to read Parquet buffer with Arrow JS...");
        let table;
        try {
            // This assumes the buffer contains Arrow IPC stream format derived from Parquet.
            // Check Arrow JS docs if there's a direct Parquet-to-Table function.
            const reader = RecordBatchStreamReader.from(parquetUint8Array);
            table = await reader.readAll(); // Reads all batches into memory - consider streaming for huge files

            if (!table || table.numRows === 0) {
                 console.warn(`Arrow JS read the Parquet file ('${PARQUET_OBJECT_KEY}'), but it resulted in an empty table or null.`);
                 // Allow proceeding, aggregation will just be empty
            } else {
                 console.log(`Arrow JS read Parquet into a table with ${table.numRows} rows and ${table.numCols} columns.`);
                 // Optional: Log schema for debugging
                 console.log("Arrow Table Schema:", table.schema.toString());
            }

        } catch (arrowError) {
            console.error(`Apache Arrow failed to read or parse the Parquet buffer from '${PARQUET_OBJECT_KEY}':`, arrowError);
            throw new Error(`Failed to process Parquet data using Arrow: ${arrowError.message}`);
        }

        // 4. Aggregate data in JavaScript (Replaces SQL GROUP BY / SUM)
        console.log("Aggregating Parquet data using JavaScript...");
        const aggregationMap = new Map(); // Map<Origin_tract (string), totalWeightedSum (number)>

        // *** CRITICAL VERIFICATION NEEDED for column names in PARQUET ***
        const originCol = "Origin_tract"; // Verify this exact column name in your Parquet file
        const weightCol = "perc_visit";   // Verify this exact column name in your Parquet file
        const requiredZscoreDCols = selectedVarsJS.map(jsVar => `${jsVar.replace(/ /g, '')}_zscore_d`); // Verify this naming convention

        // Check if required columns exist in the table schema (robustness check)
        const schema = table.schema;
        const requiredCols = [originCol, weightCol, ...requiredZscoreDCols];
        const missingCols = requiredCols.filter(colName => !schema.fields.some(field => field.name === colName));

        if (missingCols.length > 0) {
            console.error(`Missing required columns in Parquet file ('${PARQUET_OBJECT_KEY}'): ${missingCols.join(', ')}`);
            throw new Error(`Parquet data is missing required columns for calculation: ${missingCols.join(', ')}`);
        }

        // Iterate through Arrow Table rows - handle potential nulls safely
        for (const row of table) { // Assumes `table` is iterable
            const originTract = row.get(originCol)?.toString().trim(); // Get origin tract, ensure string, trim whitespace
            const weight = Number(row.get(weightCol) ?? 0); // Get weight, default null/undefined/NaN to 0

            // Skip rows with missing origin or zero/invalid weight (can't contribute to weighted sum)
            if (!originTract || !weight || isNaN(weight)) {
                continue;
            }

            let rowWeightedSum = 0;
            for (const zscoreCol of requiredZscoreDCols) {
                const zscoreValue = Number(row.get(zscoreCol) ?? 0); // Get z-score, default null/undefined/NaN to 0
                // Check zscoreValue is a valid number before multiplying
                if (!isNaN(zscoreValue)) {
                    rowWeightedSum += (zscoreValue * weight);
                }
            }

            // Add the sum for this row to the total for its origin tract
            const currentSum = aggregationMap.get(originTract) || 0;
            aggregationMap.set(originTract, currentSum + rowWeightedSum);
        }
        console.log(`JavaScript aggregation complete. Found data for ${aggregationMap.size} origin tracts.`);

        // 5. Process Aggregated Results into Final Index Values Map
        const calculatedIndexValues = new Map();
        for (const [originTract, totalSum] of aggregationMap.entries()) {
            // Ensure we have valid data before final calculation
            if (originTract != null && totalSum != null && !isNaN(totalSum)) {
                 // *** VERIFY FINAL CALCULATION ***
                 // Apply the * 100 multiplier if required by the index definition
                const finalIndexValue = totalSum * 100;
                calculatedIndexValues.set(originTract, finalIndexValue); // Map key is already trimmed string
            }
        }
        console.log(`Processed aggregated results into final map for ${calculatedIndexValues.size} origin tracts.`);

        // 6. Merge calculated values back into the main geojsonData
        let mergeCount = 0;
        let featuresProcessed = 0;
        geojsonData.features.forEach(feature => {
             featuresProcessed++;
             if (!feature.properties) feature.properties = {};
             // Use the same key format as the map (string, trimmed)
             const featureOriginId = feature.properties['Origin_tract']?.toString().trim();

             if (featureOriginId && calculatedIndexValues.has(featureOriginId)) {
                feature.properties[indexColName] = calculatedIndexValues.get(featureOriginId);
                mergeCount++;
            } else {
                // Assign null if no calculation result for this tract (important!)
                feature.properties[indexColName] = null;
            }
        });
        console.log(`Merged activity index values into ${mergeCount} / ${featuresProcessed} features as ${indexColName}.`);
        if (featuresProcessed > 0 && mergeCount === 0 && calculatedIndexValues.size > 0) {
            // This condition suggests the aggregation worked, but the merge failed.
             console.warn(`WARNING: Activity index merge resulted in null for ALL features for index '${indexColName}', even though calculations were performed. Check if 'Origin_tract' values/format match EXACTLY between GeoJSON and Parquet.`);
        } else if (featuresProcessed > 0 && calculatedIndexValues.size === 0) {
             console.warn(`WARNING: Activity index aggregation resulted in no data. Check Parquet file content and column names ('${originCol}', '${weightCol}', Z-score columns).`);
        }


        // 7. Return Modified GeoJSON
        return new Response(JSON.stringify(geojsonData), {
            status: 200, headers: responseHeaders
        });

    } catch (err) {
        console.error(`Error generating activity index using Arrow JS:`, err);
        const status = err.status || 500; // Use status from error if available
        return new Response(JSON.stringify({ error: err.message || 'Failed to generate activity index.' }), {
             status: status, headers: { ...responseHeaders, 'Content-Type': 'application/json' } // Error is JSON
        });
    }
});


// --- Catch-all for 404s ---
// This should be the LAST route added
router.all('*', (request) => {
    // Use itty-router error helper for consistency
    return error(404, 'API route not found.', { headers: request.corsHeaders });
});

// --- Main Export for Cloudflare Pages Functions ---
export async function onRequest(context) {
    // context includes: request, env, params, waitUntil, next, data
    const { request, env, ctx } = context; // Use ctx for waitUntil if needed

    try {
        // itty-router's handle method will manage routing and errors within routes
        // It returns a Response object or throws an error
        const response = await router.handle(request, env, ctx);

        // Apply CORS headers stored on the request by the middleware TO THE FINAL RESPONSE
        // This is crucial because the middleware runs *before* the route handler creates the response
        const finalHeaders = new Headers(response.headers); // Clone existing headers from the response

        // Merge CORS headers determined by the middleware, but only if they exist
        Object.entries(request.corsHeaders || {}).forEach(([key, value]) => {
            // Only set if the middleware determined the header should be set (e.g., Access-Control-Allow-Origin was set)
            if (value) { // Check if value is truthy (exists and not empty/null)
                 finalHeaders.set(key, value);
            }
        });

        // Ensure Content-Type is set correctly (itty-router's json/error helpers usually do this)
        if (!finalHeaders.has('Content-Type') && response.body && response.status !== 204 && response.status !== 304) {
             console.warn("Response from route handler missing Content-Type header. Check route handler.");
             // Defaulting might hide issues in route handlers, maybe remove default?
             // finalHeaders.set('Content-Type', 'application/json');
        }

        return new Response(response.body, {
            status: response.status,
            statusText: response.statusText,
            headers: finalHeaders // Use the merged headers
        });

    } catch (err) {
        // Catch unexpected errors *outside* of itty-router's handled routes (e.g., issue in middleware itself)
        console.error("Unhandled exception during request processing:", err);
        // Try to apply basic CORS headers even for critical errors
        const errorHeaders = { 'Access-Control-Allow-Origin': '*', 'Content-Type': 'application/json' }; // Fallback CORS
        return new Response(JSON.stringify({ error: 'Internal Server Error' }), {
            status: 500,
            headers: errorHeaders
        });
    }
}