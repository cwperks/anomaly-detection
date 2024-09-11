/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.timeseries;

import static org.opensearch.timeseries.TestHelpers.toHttpEntity;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URISyntaxException;
import java.nio.charset.Charset;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.NavigableSet;
import java.util.Random;
import java.util.TreeSet;

import org.apache.commons.lang3.tuple.Pair;
import org.apache.hc.core5.http.HttpHeaders;
import org.apache.hc.core5.http.message.BasicHeader;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.Logger;
import org.opensearch.client.Request;
import org.opensearch.client.RequestOptions;
import org.opensearch.client.Response;
import org.opensearch.client.RestClient;
import org.opensearch.client.WarningsHandler;
import org.opensearch.common.xcontent.json.JsonXContent;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.timeseries.AbstractSyntheticDataTest.MISSING_MODE;
import org.opensearch.timeseries.settings.TimeSeriesSettings;

import com.google.common.collect.ImmutableList;
import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.stream.JsonReader;

public class AbstractSyntheticDataTest extends ODFERestTestCase {
    public enum MISSING_MODE {
        MISSING_TIMESTAMP, // missing all entities in a timestamps
        MISSING_ENTITY, // missing single entity，
        NO_MISSING_DATA, // no missing data
        CONTINUOUS_IMPUTE, // vs random missing as above
    }

    public static class GenData {
        public List<JsonObject> data;
        // record missing entities and its timestamp in test data
        public NavigableSet<Pair<Long, String>> missingEntities;
        // record missing timestamps in test data
        public NavigableSet<Long> missingTimestamps;
        public long testStartTime;

        public GenData(
            List<JsonObject> data,
            NavigableSet<Pair<Long, String>> missingEntities,
            NavigableSet<Long> missingTimestamps,
            long testStartTime
        ) {
            super();
            this.data = data;
            this.missingEntities = missingEntities;
            this.missingTimestamps = missingTimestamps;
            this.testStartTime = testStartTime;
        }
    }

    public static final Logger LOG = (Logger) LogManager.getLogger(AbstractSyntheticDataTest.class);
    public static final String SYNTHETIC_DATA_MAPPING = "{ \"mappings\": { \"properties\": { \"timestamp\": { \"type\": \"date\"},"
        + " \"Feature1\": { \"type\": \"double\" }, \"Feature2\": { \"type\": \"double\" } } } }";
    public static final String RULE_DATA_MAPPING = "{ \"mappings\": { \"properties\": { \"timestamp\": { \"type\":"
        + "\"date\""
        + "},"
        + " \"transform._doc_count\": { \"type\": \"integer\" },"
        + "\"componentName\": { \"type\": \"keyword\"} } } }";
    public static final String SYNTHETIC_DATASET_NAME = "synthetic";
    public static final String RULE_DATASET_NAME = "rule";
    public static final String UNIFORM_DATASET_NAME = "uniform";
    public static int batchSize = 1000;

    /**
     * In real time AD, we mute a node for a detector if that node keeps returning
     * ResourceNotFoundException (5 times in a row).  This is a problem for batch mode
     * testing as we issue a large amount of requests quickly. Due to the speed, we
     * won't be able to finish cold start before the ResourceNotFoundException mutes
     * a node.  Since our test case has only one node, there is no other nodes to fall
     * back on.  Here we disable such fault tolerance by setting max retries before
     * muting to a large number and the actual wait time during muting to 0.
     *
     * @throws IOException when failing to create http request body
     */
    protected void disableResourceNotFoundFaultTolerence() throws IOException {
        XContentBuilder settingCommand = JsonXContent.contentBuilder();

        settingCommand.startObject();
        settingCommand.startObject("persistent");
        settingCommand.field(TimeSeriesSettings.MAX_RETRY_FOR_UNRESPONSIVE_NODE.getKey(), 100_000);
        settingCommand.field(TimeSeriesSettings.BACKOFF_MINUTES.getKey(), 0);
        settingCommand.endObject();
        settingCommand.endObject();
        Request request = new Request("PUT", "/_cluster/settings");
        request.setJsonEntity(settingCommand.toString());

        adminClient().performRequest(request);
    }

    public static void waitAllSyncheticDataIngested(int expectedSize, String datasetName, RestClient client) throws Exception {
        int maxWaitCycles = 3;
        do {
            Request request = new Request("POST", String.format(Locale.ROOT, "/%s/_search", datasetName));
            request
                .setJsonEntity(
                    String
                        .format(
                            Locale.ROOT,
                            "{\"query\": {"
                                + "        \"match_all\": {}"
                                + "    },"
                                + "    \"size\": 1,"
                                + "    \"sort\": ["
                                + "       {"
                                + "         \"timestamp\": {"
                                + "           \"order\": \"desc\""
                                + "         }"
                                + "       }"
                                + "   ]}"
                        )
                );
            // Make sure all of the test data has been ingested
            JsonArray hits = getHits(client, request);
            LOG.info("Latest synthetic data:" + hits);
            if (hits != null && hits.size() == 1 && isIdExpected(expectedSize, hits)) {
                break;
            } else {
                request = new Request("POST", String.format(Locale.ROOT, "/%s/_refresh", datasetName));
                client.performRequest(request);
            }
            Thread.sleep(1_000);
        } while (maxWaitCycles-- >= 0);
    }

    private static boolean isIdExpected(int expectedSize, JsonArray hits) {
        // we won't have more than 3 entities with the same timestamp to make the test fast
        int delta = 3;
        for (int i = 0; i < hits.size(); i++) {
            if (expectedSize - 1 <= hits.get(0).getAsJsonObject().getAsJsonPrimitive("_id").getAsLong() + delta) {
                return true;
            }
        }
        return false;
    }

    public static JsonArray getHits(RestClient client, Request request) throws IOException {
        Response response = client.performRequest(request);
        return parseHits(response);
    }

    public static JsonArray parseHits(Response response) throws IOException {
        JsonObject json = JsonParser
            .parseReader(new InputStreamReader(response.getEntity().getContent(), Charset.defaultCharset()))
            .getAsJsonObject();
        JsonObject hits = json.getAsJsonObject("hits");
        if (hits == null) {
            return null;
        }
        return hits.getAsJsonArray("hits");
    }

    protected static void bulkIndexTrainData(
        String datasetName,
        List<JsonObject> data,
        int trainTestSplit,
        RestClient client,
        String mapping
    ) throws Exception {
        createIndex(datasetName, client, mapping);

        StringBuilder bulkRequestBuilder = new StringBuilder();
        for (int i = 0; i < trainTestSplit; i++) {
            bulkRequestBuilder.append("{ \"index\" : { \"_index\" : \"" + datasetName + "\", \"_id\" : \"" + i + "\" } }\n");
            bulkRequestBuilder.append(data.get(i).toString()).append("\n");
        }
        TestHelpers
            .makeRequest(
                client,
                "POST",
                "_bulk?refresh=true",
                null,
                toHttpEntity(bulkRequestBuilder.toString()),
                ImmutableList.of(new BasicHeader(HttpHeaders.USER_AGENT, "Kibana"))
            );
        Thread.sleep(1_000);
        waitAllSyncheticDataIngested(trainTestSplit, datasetName, client);
    }

    public static void createIndex(String datasetName, RestClient client, String mapping) throws IOException, InterruptedException {
        Request request = new Request("PUT", datasetName);
        request.setJsonEntity(mapping);
        setWarningHandler(request, false);
        client.performRequest(request);
        Thread.sleep(1_000);
    }

    public static void setWarningHandler(Request request, boolean strictDeprecationMode) {
        RequestOptions.Builder options = RequestOptions.DEFAULT.toBuilder();
        options.setWarningsHandler(strictDeprecationMode ? WarningsHandler.STRICT : WarningsHandler.PERMISSIVE);
        request.setOptions(options.build());
    }

    /**
     * Read data from a json array file up to a specified size
     * @param datasetFileName data set file name
     * @param size the limit of json elements to read
     * @return the read JsonObject list
     * @throws URISyntaxException when failing to find datasetFileName
     * @throws Exception when there is a parsing error.
     */
    public static List<JsonObject> readJsonArrayWithLimit(String datasetFileName, int limit) throws URISyntaxException {
        List<JsonObject> jsonObjects = new ArrayList<>();
        try (
            FileReader fileReader = new FileReader(
                new File(AbstractSyntheticDataTest.class.getClassLoader().getResource(datasetFileName).toURI()),
                Charset.defaultCharset()
            );
            JsonReader jsonReader = new JsonReader(fileReader)
        ) {

            Gson gson = new Gson();
            JsonArray jsonArray = gson.fromJson(jsonReader, JsonArray.class);

            for (int i = 0; i < limit && i < jsonArray.size(); i++) {
                JsonObject jsonObject = jsonArray.get(i).getAsJsonObject();
                jsonObjects.add(jsonObject);
            }

        } catch (IOException e) {
            LOG.error("fail to read json array", e);
        }
        return jsonObjects;
    }

    /**
     *
     * @param datasetName Data set name
     * @param trainTestSplit the number of rows in training data
     * @return train time
     * @throws Exception when failing to ingest data
     */
    private static Instant loadData(String datasetName, int trainTestSplit, String mapping) throws Exception {
        RestClient client = client();

        String dataFileName = String.format(Locale.ROOT, "org/opensearch/ad/e2e/data/%s.data", datasetName);

        List<JsonObject> data = readJsonArrayWithLimit(dataFileName, trainTestSplit);

        bulkIndexTrainData(datasetName, data, trainTestSplit, client, mapping);
        String trainTimeStr = data.get(trainTestSplit - 1).get("timestamp").getAsString();
        if (canBeParsedAsLong(trainTimeStr)) {
            return Instant.ofEpochMilli(Long.parseLong(trainTimeStr));
        } else {
            return Instant.parse(trainTimeStr);
        }

    }

    protected static Instant loadSyntheticData(int trainTestSplit) throws Exception {
        return loadData(SYNTHETIC_DATASET_NAME, trainTestSplit, SYNTHETIC_DATA_MAPPING);
    }

    protected static Instant loadRuleData(int trainTestSplit) throws Exception {
        return loadData(RULE_DATASET_NAME, trainTestSplit, RULE_DATA_MAPPING);
    }

    public static boolean canBeParsedAsLong(String str) {
        if (str == null || str.isEmpty()) {
            return false; // Handle null or empty strings as not parsable
        }

        try {
            Long.parseLong(str);
            return true;
        } catch (NumberFormatException e) {
            return false;
        }
    }

    public static List<Double> generateUniformRandomDoubles(int size, double min, double max) {
        List<Double> randomDoubles = new ArrayList<>(size);
        Random random = new Random(0);

        for (int i = 0; i < size; i++) {
            double randomValue = min + (max - min) * random.nextDouble();
            randomDoubles.add(randomValue);
        }

        return randomDoubles;
    }

    protected JsonObject createJsonObject(long timestamp, String component, double dataValue, String categoricalField) {
        JsonObject jsonObject = new JsonObject();
        jsonObject.addProperty("timestamp", timestamp);
        jsonObject.addProperty(categoricalField, component);
        jsonObject.addProperty("data", dataValue);
        return jsonObject;
    }

    public GenData genUniformSingleFeatureData(
        int intervalMinutes,
        int trainTestSplit,
        int numberOfEntities,
        String categoricalField,
        MISSING_MODE missingMode,
        int continuousImputeStartIndex,
        int continuousImputeEndIndex,
        List<Double> randomDoubles
    ) {
        List<JsonObject> data = new ArrayList<>();
        long currentTime = System.currentTimeMillis();
        long intervalMillis = intervalMinutes * 60000L;
        long timestampMillis = currentTime - intervalMillis * trainTestSplit / numberOfEntities;
        LOG.info("begin timestamp: {}", timestampMillis);
        int entityIndex = 0;
        NavigableSet<Pair<Long, String>> missingEntities = new TreeSet<>();
        NavigableSet<Long> missingTimestamps = new TreeSet<>();
        long testStartTime = 0;
        Random random = new Random();

        for (int i = 0; i < randomDoubles.size();) {
            // we won't miss the train time (the first point triggering cold start)
            if (timestampMillis > currentTime && testStartTime == 0) {
                LOG.info("test start time {}, index {}, current time {}", timestampMillis, data.size(), currentTime);
                testStartTime = timestampMillis;

                for (int j = 0; j < numberOfEntities; j++) {
                    JsonObject jsonObject = createJsonObject(
                        timestampMillis,
                        "entity" + entityIndex,
                        randomDoubles.get(i++),
                        categoricalField
                    );
                    entityIndex = (entityIndex + 1) % numberOfEntities;
                    data.add(jsonObject);
                }
                timestampMillis += intervalMillis;

                continue;
            }

            if (shouldSkipDataPoint(
                missingMode,
                entityIndex,
                testStartTime,
                timestampMillis,
                random,
                intervalMillis,
                continuousImputeStartIndex,
                continuousImputeEndIndex
            )) {
                if (timestampMillis > currentTime) {
                    if (missingMode == MISSING_MODE.MISSING_TIMESTAMP || missingMode == MISSING_MODE.CONTINUOUS_IMPUTE) {
                        missingTimestamps.add(timestampMillis);
                    } else if (missingMode == MISSING_MODE.MISSING_ENTITY) {
                        missingEntities.add(Pair.of(timestampMillis, "entity" + entityIndex));
                        entityIndex = (entityIndex + 1) % numberOfEntities;
                        if (entityIndex == 0) {
                            timestampMillis += intervalMillis;
                        }
                    }
                }

                if (missingMode == MISSING_MODE.MISSING_TIMESTAMP || missingMode == MISSING_MODE.CONTINUOUS_IMPUTE) {
                    timestampMillis += intervalMillis;
                }
            } else {
                JsonObject jsonObject = createJsonObject(timestampMillis, "entity" + entityIndex, randomDoubles.get(i), categoricalField);
                data.add(jsonObject);
                entityIndex = (entityIndex + 1) % numberOfEntities;
                if (entityIndex == 0) {
                    timestampMillis += intervalMillis;
                }
            }

            i++;
        }
        LOG
            .info(
                "begin timestamp: {}, end timestamp: {}",
                data.get(0).get("timestamp").getAsLong(),
                data.get(data.size() - 1).get("timestamp").getAsLong()
            );
        return new GenData(data, missingEntities, missingTimestamps, testStartTime);
    }

    public GenData genUniformSingleFeatureData(
        int intervalMinutes,
        int trainTestSplit,
        int numberOfEntities,
        String categoricalField,
        MISSING_MODE missingMode,
        int continuousImputeStartIndex,
        int continuousImputeEndIndex,
        int dataSize
    ) {
        List<Double> randomDoubles = generateUniformRandomDoubles(dataSize, 200, 300);

        return genUniformSingleFeatureData(
            intervalMinutes,
            trainTestSplit,
            numberOfEntities,
            categoricalField,
            missingMode,
            continuousImputeStartIndex,
            continuousImputeEndIndex,
            randomDoubles
        );
    }

    protected boolean shouldSkipDataPoint(
        AbstractSyntheticDataTest.MISSING_MODE missingMode,
        int entityIndex,
        long testStartTime,
        long currentTime,
        Random random,
        long intervalMillis,
        int continuousImputeStartIndex,
        int continuousImputeEndIndex
    ) {
        if (testStartTime == 0 || missingMode == AbstractSyntheticDataTest.MISSING_MODE.NO_MISSING_DATA) {
            return false;
        }
        if (missingMode == AbstractSyntheticDataTest.MISSING_MODE.MISSING_TIMESTAMP && entityIndex == 0) {
            return random.nextDouble() > 0.5;
        } else if (missingMode == AbstractSyntheticDataTest.MISSING_MODE.MISSING_ENTITY) {
            return random.nextDouble() > 0.5;
        } else if (missingMode == AbstractSyntheticDataTest.MISSING_MODE.CONTINUOUS_IMPUTE && entityIndex == 0) {
            long delta = (currentTime - testStartTime) / intervalMillis;
            // start missing in a range
            return delta >= continuousImputeStartIndex && delta <= continuousImputeEndIndex;
        }
        return false;
    }

    protected void bulkIndexData(List<JsonObject> data, String datasetName, RestClient client, String mapping, int ingestDataSize)
        throws Exception {
        createIndex(datasetName, client, mapping);
        StringBuilder bulkRequestBuilder = new StringBuilder();
        LOG.info("data size {}", data.size());
        int count = 0;
        int pickedIngestSize = Math.min(ingestDataSize, data.size());
        LOG.info("ingest size {}", pickedIngestSize);
        for (int i = 0; i < pickedIngestSize; i++) {
            bulkRequestBuilder.append("{ \"index\" : { \"_index\" : \"" + datasetName + "\", \"_id\" : \"" + i + "\" } }\n");
            bulkRequestBuilder.append(data.get(i).toString()).append("\n");
            count++;
            if (count >= batchSize || i == pickedIngestSize - 1) {
                count = 0;
                TestHelpers
                    .makeRequest(
                        client,
                        "POST",
                        "_bulk?refresh=true",
                        null,
                        toHttpEntity(bulkRequestBuilder.toString()),
                        ImmutableList.of(new BasicHeader(HttpHeaders.USER_AGENT, "Kibana"))
                    );
                Thread.sleep(1_000);
            }
        }

        waitAllSyncheticDataIngested(data.size(), datasetName, client);
        LOG.info("data ingestion complete");
    }

    protected void ingestUniformSingleFeatureData(int ingestDataSize, List<JsonObject> data, String datasetName, String categoricalField)
        throws Exception {

        RestClient client = client();

        String mapping = String
            .format(
                Locale.ROOT,
                "{ \"mappings\": { \"properties\": { \"timestamp\": { \"type\":"
                    + "\"date\""
                    + "},"
                    + " \"data\": { \"type\": \"double\" },"
                    + "\"%s\": { \"type\": \"keyword\"} } } }",
                categoricalField
            );

        if (ingestDataSize <= 0) {
            bulkIndexData(data, datasetName, client, mapping, data.size());
        } else {
            bulkIndexData(data, datasetName, client, mapping, ingestDataSize);
        }
    }
}