/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */

package org.opensearch.ad.rest;

import static org.opensearch.ad.util.RestHandlerUtils.getSourceContext;
import static org.opensearch.core.xcontent.ToXContent.EMPTY_PARAMS;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.lang3.tuple.Pair;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.ActionType;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.ad.constant.ADCommonMessages;
import org.opensearch.ad.settings.ADEnabledSetting;
import org.opensearch.client.node.NodeClient;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.NamedRoute;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.RestResponse;
import org.opensearch.rest.RestStatus;
import org.opensearch.rest.action.RestResponseListener;
import org.opensearch.search.builder.SearchSourceBuilder;

/**
 * Abstract class to handle search request.
 */
public abstract class AbstractSearchAction<T extends ToXContentObject> extends BaseRestHandler {

    protected final String index;
    protected final Class<T> clazz;
    protected final List<String> urlPaths;
    protected final List<Pair<String, String>> deprecatedPaths;
    protected final ActionType<SearchResponse> actionType;

    protected String restActionName;

    private final Logger logger = LogManager.getLogger(AbstractSearchAction.class);

    public AbstractSearchAction(
        List<String> urlPaths,
        List<Pair<String, String>> deprecatedPaths,
        String index,
        Class<T> clazz,
        ActionType<SearchResponse> actionType
    ) {
        this.index = index;
        this.clazz = clazz;
        this.urlPaths = urlPaths;
        this.deprecatedPaths = deprecatedPaths;
        this.actionType = actionType;
    }

    public AbstractSearchAction(
        List<String> urlPaths,
        List<Pair<String, String>> deprecatedPaths,
        String index,
        Class<T> clazz,
        ActionType<SearchResponse> actionType,
        String restActionName
    ) {
        this.index = index;
        this.clazz = clazz;
        this.urlPaths = urlPaths;
        this.deprecatedPaths = deprecatedPaths;
        this.actionType = actionType;
        this.restActionName = restActionName;
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) throws IOException {
        if (!ADEnabledSetting.isADEnabled()) {
            throw new IllegalStateException(ADCommonMessages.DISABLED_ERR_MSG);
        }
        SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder();
        searchSourceBuilder.parseXContent(request.contentOrSourceParamParser());
        // order of response will be re-arranged everytime we use `_source`, we sometimes do this
        // even if user doesn't give this field as we exclude ui_metadata if request isn't from OSD
        // ref-link: https://github.com/elastic/elasticsearch/issues/17639
        searchSourceBuilder.fetchSource(getSourceContext(request, searchSourceBuilder));
        searchSourceBuilder.seqNoAndPrimaryTerm(true).version(true);
        SearchRequest searchRequest = new SearchRequest().source(searchSourceBuilder).indices(this.index);
        return channel -> client.execute(actionType, searchRequest, search(channel));
    }

    protected void onFailure(RestChannel channel, Exception e) {
        try {
            channel.sendResponse(new BytesRestResponse(channel, e));
        } catch (Exception exception) {
            logger.error("Failed to send back failure response for search AD result", exception);
        }
    }

    protected RestResponseListener<SearchResponse> search(RestChannel channel) {
        return new RestResponseListener<SearchResponse>(channel) {
            @Override
            public RestResponse buildResponse(SearchResponse response) throws Exception {
                if (response.isTimedOut()) {
                    return new BytesRestResponse(RestStatus.REQUEST_TIMEOUT, response.toString());
                }
                return new BytesRestResponse(RestStatus.OK, response.toXContent(channel.newBuilder(), EMPTY_PARAMS));
            }
        };
    }

    @Override
    public List<Route> routes() {
        List<Route> routes = new ArrayList<>();
        for (String path : urlPaths) {
            if (restActionName != null) {
                routes.add(new NamedRoute(RestRequest.Method.POST, path, restActionName));
                routes.add(new NamedRoute(RestRequest.Method.GET, path, restActionName));
            } else {
                routes.add(new Route(RestRequest.Method.POST, path));
                routes.add(new Route(RestRequest.Method.GET, path));
            }
        }
        return routes;
    }

    @Override
    public List<ReplacedRoute> replacedRoutes() {
        List<ReplacedRoute> replacedRoutes = new ArrayList<>();
        for (Pair<String, String> deprecatedPath : deprecatedPaths) {
            replacedRoutes
                .add(
                    new ReplacedRoute(RestRequest.Method.POST, deprecatedPath.getKey(), RestRequest.Method.POST, deprecatedPath.getValue())
                );
            replacedRoutes
                .add(new ReplacedRoute(RestRequest.Method.GET, deprecatedPath.getKey(), RestRequest.Method.GET, deprecatedPath.getValue()));

        }
        return replacedRoutes;
    }
}
