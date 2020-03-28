/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License").
 *  You may not use this file except in compliance with the License.
 *  A copy of the License is located at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  or in the "license" file accompanying this file. This file is distributed
 *  on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 *  express or implied. See the License for the specific language governing
 *  permissions and limitations under the License.
 */

package com.amazon.opendistroforelasticsearch.security.dlic.rest.api;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import com.amazon.opendistroforelasticsearch.security.DefaultObjectMapper;
import com.amazon.opendistroforelasticsearch.security.dlic.rest.support.Utils;
import com.amazon.opendistroforelasticsearch.security.dlic.rest.validation.SecurityConfigValidator;
import com.amazon.opendistroforelasticsearch.security.securityconf.impl.CType;
import com.amazon.opendistroforelasticsearch.security.securityconf.impl.SecurityDynamicConfiguration;
import com.amazon.opendistroforelasticsearch.security.securityconf.impl.v6.ConfigV6;
import com.amazon.opendistroforelasticsearch.security.securityconf.impl.v7.ConfigV7;
import com.amazon.opendistroforelasticsearch.security.support.SecurityJsonNode;
import com.amazon.opendistroforelasticsearch.security.transport.NodesDnProvider;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.elasticsearch.action.index.IndexResponse;
import org.elasticsearch.client.Client;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.rest.RestChannel;
import org.elasticsearch.rest.RestController;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.rest.RestRequest.Method;
import org.elasticsearch.threadpool.ThreadPool;

import com.fasterxml.jackson.databind.JsonNode;
import com.amazon.opendistroforelasticsearch.security.auditlog.AuditLog;
import com.amazon.opendistroforelasticsearch.security.configuration.AdminDNs;
import com.amazon.opendistroforelasticsearch.security.configuration.ConfigurationRepository;
import com.amazon.opendistroforelasticsearch.security.dlic.rest.validation.AbstractConfigurationValidator;
import com.amazon.opendistroforelasticsearch.security.privileges.PrivilegesEvaluator;
import com.amazon.opendistroforelasticsearch.security.ssl.transport.PrincipalExtractor;
import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;

public class OpenDistroSecurityConfigAction extends PatchableResourceApiAction {

    private final boolean allowPutOrPatch;

    @Inject
    public OpenDistroSecurityConfigAction(final Settings settings, final Path configPath, final RestController controller, final Client client,
                          final AdminDNs adminDNs, final ConfigurationRepository cl, final ClusterService cs,
                          final PrincipalExtractor principalExtractor, final PrivilegesEvaluator evaluator, ThreadPool threadPool, AuditLog auditLog) {

        super(settings, configPath, controller, client, adminDNs, cl, cs, principalExtractor, evaluator, threadPool, auditLog);
        allowPutOrPatch = settings.getAsBoolean(ConfigConstants.OPENDISTRO_SECURITY_UNSUPPORTED_RESTAPI_ALLOW_SECURITYCONFIG_MODIFICATION, false);

    }

    @Override
    protected void registerHandlers(RestController controller, Settings settings) {
        controller.registerHandler(Method.GET, "/_opendistro/_security/api/securityconfig/", this);

        //controller.registerHandler(Method.GET, "/_opendistro/_security/api/config/", this);

        boolean enablePutOrPatch = settings.getAsBoolean(ConfigConstants.OPENDISTRO_SECURITY_UNSUPPORTED_RESTAPI_ALLOW_SECURITYCONFIG_MODIFICATION, false);
        if (enablePutOrPatch) {

            //deprecated, will be removed with ODFE 8, use opendistro_security_config instead of config
            controller.registerHandler(Method.PUT, "/_opendistro/_security/api/securityconfig/{name}", this);
            controller.registerHandler(Method.PATCH, "/_opendistro/_security/api/securityconfig/", this);
        }
    }


    @Override
    protected void handleGet(RestChannel channel, RestRequest request, Client client, final JsonNode content) throws IOException{
        final SecurityDynamicConfiguration<?> configuration = load(getConfigName(), true);

        filter(configuration);
        filterAdminSectionIfApplicable(configuration);

        successResponse(channel, configuration);
    }

    private void filterAdminSectionIfApplicable(SecurityDynamicConfiguration<?> configuration) {
        if (!isSuperAdmin()) {
            if(configuration.getImplementingClass() == ConfigV7.class) {
                ConfigV7 config = getConfigV7(configuration);
                config.dynamic.admin = null;
            } else {
                ConfigV6 config = getConfigV6(configuration);
                config.dynamic.admin = null;
            }
        }
    }

    private static ConfigV6 getConfigV6(SecurityDynamicConfiguration<?> sdc) {
        @SuppressWarnings("unchecked")
        SecurityDynamicConfiguration<ConfigV6> c = (SecurityDynamicConfiguration<ConfigV6>) sdc;
        return c.getCEntry("opendistro_security");
    }

    private static ConfigV7 getConfigV7(SecurityDynamicConfiguration<?> sdc) {
        @SuppressWarnings("unchecked")
        SecurityDynamicConfiguration<ConfigV7> c = (SecurityDynamicConfiguration<ConfigV7>) sdc;
        return c.getCEntry("config");
    }

    @Override
    protected void handleApiRequest(RestChannel channel, RestRequest request, Client client) throws IOException {
        if (request.method() == Method.PATCH && !allowPutOrPatch) {
            notImplemented(channel, Method.PATCH);
        } else {
            super.handleApiRequest(channel, request, client);
        }
    }

    @Override
    protected void handlePut(RestChannel channel, final RestRequest request, final Client client, final JsonNode content) throws IOException{
        if (allowPutOrPatch) {

            if(!"config".equals(request.param("name"))) {
                badRequestResponse(channel, "name must be config");
                return;
            }

            final String name = request.param("name");

            if (name == null || name.length() == 0) {
                badRequestResponse(channel, "No " + getResourceName() + " specified.");
                return;
            }

            final SecurityDynamicConfiguration<?> existingConfiguration = load(getConfigName(), false);

            if (isHidden(existingConfiguration, name)) {
                forbidden(channel, "Resource '"+ name +"' is not available.");
                return;
            }

            if (!isReservedAndAccessible(existingConfiguration, name)) {
                forbidden(channel, "Resource '"+ name +"' is read-only.");
                return;
            }

            if (log.isTraceEnabled() && content != null) {
                log.trace(content.toString());
            }
            JsonNode existingAsJsonNode = Utils.convertJsonToJackson(existingConfiguration, false);

            if (!(existingAsJsonNode instanceof ObjectNode)) {
                internalErrorResponse(channel, "Config " + getConfigName() + " is malformed");
                return;
            }

            final SecurityJsonNode existingAsSecurityJsonNode = new SecurityJsonNode(existingAsJsonNode);
            final SecurityJsonNode securityJsonNode = new SecurityJsonNode(content);

            final List<String> existingEsYmlNodesDn = getNodesDnFromConfig(existingAsSecurityJsonNode);
            final List<String> payloadEsYmlNodesDn = getNodesDnFromConfig(securityJsonNode);

            log.debug("Comparing dynamic/admin/nodes_dn/{} values - Existing: {}, Payload: {}",
                NodesDnProvider.ES_YML_NODES_DN_KEY, existingEsYmlNodesDn, payloadEsYmlNodesDn);

            // We allow setting
            if (null != payloadEsYmlNodesDn && !areListsEqualOrderInsensitive(existingEsYmlNodesDn, payloadEsYmlNodesDn)) {
                forbidden(channel, "dynamic/admin/nodes_dn/" + NodesDnProvider.ES_YML_NODES_DN_KEY + " cannot be " +
                    "modified");
                return;
            }

            boolean existed = existingConfiguration.exists(name);
            existingConfiguration.putCObject(name, DefaultObjectMapper.readTree(content, existingConfiguration.getImplementingClass()));

            saveAnUpdateConfigs(client, request, getConfigName(), existingConfiguration, new OnSucessActionListener<IndexResponse>(channel) {

                @Override
                public void onResponse(IndexResponse response) {
                    if (existed) {
                        successResponse(channel, "'" + name + "' updated.");
                    } else {
                        createdResponse(channel, "'" + name + "' created.");
                    }

                }
            });

        } else {
            notImplemented(channel, Method.PUT);
        }
    }

    private static List<String> getNodesDnFromConfig(SecurityJsonNode config) {
        return config.get("dynamic").get("admin").get("nodes_dn").get(NodesDnProvider.ES_YML_NODES_DN_KEY).asList();
    }

    private static boolean areListsEqualOrderInsensitive(List<String> one, List<String> two) {
        if (one == null && two == null) {
            return true;
        }

        if (one == null || two == null || (one.size() != two.size())) {
            return false;
        }

        one = new ArrayList<>(one);
        two = new ArrayList<>(two);

        Collections.sort(one);
        Collections.sort(two);

        return one.equals(two);
    }

    @Override
    protected void handlePost(RestChannel channel, final RestRequest request, final Client client, final JsonNode content) throws IOException{
        notImplemented(channel, Method.POST);
    }

    @Override
    protected void handleDelete(RestChannel channel, final RestRequest request, final Client client, final JsonNode content) throws IOException{
        notImplemented(channel, Method.DELETE);
    }

    @Override
    protected AbstractConfigurationValidator getValidator(RestRequest request, BytesReference ref, Object... param) {
        return new SecurityConfigValidator(request, ref, this.settings, param);
    }

    @Override
    protected CType getConfigName() {
        return CType.CONFIG;
    }

    @Override
    protected Endpoint getEndpoint() {
        return Endpoint.CONFIG;
    }

    @Override
    protected String getResourceName() {
        // not needed, no single resource
        return null;
    }

}
