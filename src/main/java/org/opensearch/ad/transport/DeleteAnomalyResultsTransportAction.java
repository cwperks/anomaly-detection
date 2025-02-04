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

package org.opensearch.ad.transport;

import static org.opensearch.ad.constant.ADCommonMessages.FAIL_TO_DELETE_AD_RESULT;
import static org.opensearch.ad.settings.AnomalyDetectorSettings.AD_FILTER_BY_BACKEND_ROLES;
import static org.opensearch.timeseries.util.RestHandlerUtils.wrapRestActionListener;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.client.Client;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.settings.Settings;
import org.opensearch.commons.authuser.User;
import org.opensearch.core.action.ActionListener;
import org.opensearch.index.reindex.BulkByScrollResponse;
import org.opensearch.index.reindex.DeleteByQueryAction;
import org.opensearch.index.reindex.DeleteByQueryRequest;
import org.opensearch.tasks.Task;
import org.opensearch.timeseries.util.ParseUtils;
import org.opensearch.timeseries.util.RunAsSubjectClient;
import org.opensearch.transport.TransportService;

public class DeleteAnomalyResultsTransportAction extends HandledTransportAction<DeleteByQueryRequest, BulkByScrollResponse> {

    private final Client client;
    private final RunAsSubjectClient pluginClient;
    private volatile Boolean filterEnabled;
    private static final Logger logger = LogManager.getLogger(DeleteAnomalyResultsTransportAction.class);

    @Inject
    public DeleteAnomalyResultsTransportAction(
        TransportService transportService,
        ActionFilters actionFilters,
        Settings settings,
        ClusterService clusterService,
        Client client,
        RunAsSubjectClient pluginClient
    ) {
        super(DeleteAnomalyResultsAction.NAME, transportService, actionFilters, DeleteByQueryRequest::new);
        this.client = client;
        this.pluginClient = pluginClient;
        filterEnabled = AD_FILTER_BY_BACKEND_ROLES.get(settings);
        clusterService.getClusterSettings().addSettingsUpdateConsumer(AD_FILTER_BY_BACKEND_ROLES, it -> filterEnabled = it);
    }

    @Override
    protected void doExecute(Task task, DeleteByQueryRequest request, ActionListener<BulkByScrollResponse> actionListener) {
        ActionListener<BulkByScrollResponse> listener = wrapRestActionListener(actionListener, FAIL_TO_DELETE_AD_RESULT);
        delete(request, listener);
    }

    public void delete(DeleteByQueryRequest request, ActionListener<BulkByScrollResponse> listener) {
        User user = ParseUtils.getUserContext(client);
        validateRole(request, user, listener);

    }

    private void validateRole(DeleteByQueryRequest request, User user, ActionListener<BulkByScrollResponse> listener) {
        if (user == null || !filterEnabled) {
            // Case 1: user == null when 1. Security is disabled. 2. When user is super-admin
            // Case 2: If Security is enabled and filter is disabled, proceed with search as
            // user is already authenticated to hit this API.
            pluginClient.execute(DeleteByQueryAction.INSTANCE, request, listener);
        } else {
            // Security is enabled and backend role filter is enabled
            try {
                ParseUtils.addUserBackendRolesFilter(user, request.getSearchRequest().source());
                pluginClient.execute(DeleteByQueryAction.INSTANCE, request, listener);
            } catch (Exception e) {
                listener.onFailure(e);
            }
        }
    }
}
