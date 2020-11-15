/*
 * Copyright (c) 2020, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.samlsso.manager.ext;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.common.SAMLVersion;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.common.Extensions;
import org.opensaml.saml2.core.*;
import org.opensaml.saml2.core.impl.*;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.util.Base64;
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Element;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.identity.application.authentication.framework.config.builder.FileBasedConfigurationBuilder;
import org.wso2.carbon.identity.application.authentication.framework.config.model.AuthenticatorConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authenticator.samlsso.exception.SAMLSSOException;
import org.wso2.carbon.identity.application.authenticator.samlsso.manager.DefaultSAML2SSOManager;
import org.wso2.carbon.identity.application.authenticator.samlsso.manager.X509CredentialImpl;
import org.wso2.carbon.identity.application.authenticator.samlsso.util.SSOConstants;
import org.wso2.carbon.identity.application.authenticator.samlsso.util.SSOUtils;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationManagementUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;

import javax.servlet.http.HttpServletRequest;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.Map;
import java.util.UUID;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;

public class AuthContextSAMLSSOManager extends DefaultSAML2SSOManager {

    private static Log log = LogFactory.getLog(AuthContextSAMLSSOManager.class);

    private static final String SIGN_AUTH2_SAML_USING_SUPER_TENANT = "SignAuth2SAMLUsingSuperTenant";
    private static final String NAME_ID_TYPE = "NameIDType";
    private IdentityProvider identityProvider = null;
    private Map<String, String> properties;
    private String tenantDomain;

    @Override
    public void init(String tenantDomain, Map<String, String> properties, IdentityProvider idp)
            throws SAMLSSOException {

        this.tenantDomain = tenantDomain;
        this.identityProvider = idp;
        this.properties = properties;
    }

    /**
     * Returns the redirection URL with the appended SAML2
     * Request message
     *
     * @param request SAML 2 request
     * @return redirectionUrl
     */
    @Override
    public String buildRequest(HttpServletRequest request, boolean isLogout, boolean isPassive,
                               String loginPage, AuthenticationContext context)
            throws SAMLSSOException {

        doBootstrap();
        String contextIdentifier = context.getContextIdentifier();
        RequestAbstractType requestMessage;

        if (request.getParameter(SSOConstants.HTTP_POST_PARAM_SAML2_AUTH_REQ) == null) {
            String queryParam = context.getQueryParams();
            if (queryParam != null) {
                String[] params = queryParam.split("&");
                for (String param : params) {
                    String[] values = param.split("=");
                    if (values.length == 2 && SSOConstants.HTTP_POST_PARAM_SAML2_AUTH_REQ.equals(values[0])) {
                        request.setAttribute(SSOConstants.HTTP_POST_PARAM_SAML2_AUTH_REQ, values[1]);
                        break;
                    }
                }
            }
        }
        if (!isLogout) {
            requestMessage = buildAuthnRequest(request, isPassive, loginPage, context);
        } else {
            String username = (String) request.getSession().getAttribute(SSOConstants.LOGOUT_USERNAME);
            String sessionIndex = (String) request.getSession().getAttribute(SSOConstants.LOGOUT_SESSION_INDEX);
            String nameQualifier = (String) request.getSession().getAttribute(SSOConstants.NAME_QUALIFIER);
            String spNameQualifier = (String) request.getSession().getAttribute(SSOConstants.SP_NAME_QUALIFIER);

            requestMessage = buildLogoutRequest(username, sessionIndex, loginPage, nameQualifier, spNameQualifier);
        }
        String idpUrl = null;
        boolean isSignAuth2SAMLUsingSuperTenant = false;

        String encodedRequestMessage = encodeRequestMessage(requestMessage);
        StringBuilder httpQueryString = new StringBuilder("SAMLRequest=" + encodedRequestMessage);

        try {
            httpQueryString.append("&RelayState=" + URLEncoder.encode(contextIdentifier, "UTF-8").trim());
        } catch (UnsupportedEncodingException e) {
            throw new SAMLSSOException("Error occurred while url encoding RelayState", e);
        }

        boolean isRequestSigned;
        if (!isLogout) {
            isRequestSigned = SSOUtils.isAuthnRequestSigned(properties);
        } else {
            isRequestSigned = SSOUtils.isLogoutRequestSigned(properties);
        }

        if (isRequestSigned) {
            String signatureAlgoProp = properties
                    .get(IdentityApplicationConstants.Authenticator.SAML2SSO.SIGNATURE_ALGORITHM);
            if (StringUtils.isEmpty(signatureAlgoProp)) {
                signatureAlgoProp = IdentityApplicationConstants.XML.SignatureAlgorithm.RSA_SHA1;
            }
            String signatureAlgo = IdentityApplicationManagementUtil.getXMLSignatureAlgorithms()
                    .get(signatureAlgoProp);

            Map<String, String> parameterMap = FileBasedConfigurationBuilder.getInstance()
                    .getAuthenticatorBean(SSOConstants.AUTHENTICATOR_NAME).getParameterMap();
            if (parameterMap.size() > 0) {
                isSignAuth2SAMLUsingSuperTenant = Boolean.parseBoolean(parameterMap.
                        get(SIGN_AUTH2_SAML_USING_SUPER_TENANT));
            }
            if (isSignAuth2SAMLUsingSuperTenant) {
                SSOUtils.addSignatureToHTTPQueryString(httpQueryString, signatureAlgo,
                        new X509CredentialImpl(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME, null));
            } else {
                SSOUtils.addSignatureToHTTPQueryString(httpQueryString, signatureAlgo,
                        new X509CredentialImpl(context.getTenantDomain(), null));
            }
        }
        if (loginPage.indexOf("?") > -1) {
            idpUrl = loginPage.concat("&").concat(httpQueryString.toString());
        } else {
            idpUrl = loginPage.concat("?").concat(httpQueryString.toString());
        }
        return idpUrl;
    }


    /**
     * @param request
     * @param isLogout
     * @param isPassive
     * @param loginPage
     * @return return encoded SAML Auth request
     * @throws SAMLSSOException
     */
    @Override
    public String buildPostRequest(HttpServletRequest request, boolean isLogout,
                                   boolean isPassive, String loginPage, AuthenticationContext context) throws SAMLSSOException {

        doBootstrap();
        RequestAbstractType requestMessage;
        String signatureAlgoProp = null;
        String digestAlgoProp = null;
        String includeCertProp = null;
        String signatureAlgo = null;
        String digestAlgo = null;
        boolean includeCert = false;

        // get Signature Algorithm
        signatureAlgoProp = properties
                .get(IdentityApplicationConstants.Authenticator.SAML2SSO.SIGNATURE_ALGORITHM);
        if (StringUtils.isEmpty(signatureAlgoProp)) {
            signatureAlgoProp = IdentityApplicationConstants.XML.SignatureAlgorithm.RSA_SHA1;
        }
        signatureAlgo = IdentityApplicationManagementUtil.getXMLSignatureAlgorithms().get(signatureAlgoProp);

        // get Digest Algorithm
        digestAlgoProp = properties
                .get(IdentityApplicationConstants.Authenticator.SAML2SSO.DIGEST_ALGORITHM);
        if (StringUtils.isEmpty(digestAlgoProp)) {
            digestAlgoProp = IdentityApplicationConstants.XML.DigestAlgorithm.SHA1;
        }
        digestAlgo = IdentityApplicationManagementUtil.getXMLDigestAlgorithms().get(digestAlgoProp);

        includeCertProp = properties
                .get(IdentityApplicationConstants.Authenticator.SAML2SSO.INCLUDE_CERT);
        if (StringUtils.isEmpty(includeCertProp) || Boolean.parseBoolean(includeCertProp)) {
            includeCert = true;
        }

        if (!isLogout) {
            requestMessage = buildAuthnRequest(request, isPassive, loginPage, context);
            if (SSOUtils.isAuthnRequestSigned(properties)) {
                SSOUtils.setSignature(requestMessage, signatureAlgo, digestAlgo, includeCert,
                        new X509CredentialImpl(context.getTenantDomain(), null));
            }
        } else {
            String username = (String) request.getSession().getAttribute(SSOConstants.LOGOUT_USERNAME);
            String sessionIndex = (String) request.getSession().getAttribute(SSOConstants.LOGOUT_SESSION_INDEX);
            String nameQualifier = (String) request.getSession().getAttribute(SSOConstants.NAME_QUALIFIER);
            String spNameQualifier = (String) request.getSession().getAttribute(SSOConstants.SP_NAME_QUALIFIER);

            requestMessage = buildLogoutRequest(username, sessionIndex, loginPage, nameQualifier, spNameQualifier);
            if (SSOUtils.isLogoutRequestSigned(properties)) {
                SSOUtils.setSignature(requestMessage, signatureAlgo, digestAlgo, includeCert,
                        new X509CredentialImpl(context.getTenantDomain(), null));
            }
        }

        return SSOUtils.encode(SSOUtils.marshall(requestMessage));
    }

    private AuthnRequest buildAuthnRequest(HttpServletRequest request,
                                           boolean isPassive, String idpUrl, AuthenticationContext context)
            throws SAMLSSOException {

        IssuerBuilder issuerBuilder = new IssuerBuilder();
        Issuer issuer = issuerBuilder.buildObject("urn:oasis:names:tc:SAML:2.0:assertion", "Issuer", "samlp");

        String spEntityId = properties.get(IdentityApplicationConstants.Authenticator.SAML2SSO.SP_ENTITY_ID);

        if (spEntityId != null && !spEntityId.isEmpty()) {
            issuer.setValue(spEntityId);
        } else {
            issuer.setValue("carbonServer");
        }

        DateTime issueInstant = new DateTime();

        /* Creation of AuthRequestObject */
        AuthnRequestBuilder authRequestBuilder = new AuthnRequestBuilder();
        AuthnRequest authRequest = authRequestBuilder.buildObject("urn:oasis:names:tc:SAML:2.0:protocol",
                "AuthnRequest", "samlp");
        authRequest.setForceAuthn(isForceAuthenticate(context));
        authRequest.setIsPassive(isPassive);
        authRequest.setIssueInstant(issueInstant);

        String includeProtocolBindingProp = properties
                .get(IdentityApplicationConstants.Authenticator.SAML2SSO.INCLUDE_PROTOCOL_BINDING);
        if (StringUtils.isEmpty(includeProtocolBindingProp) || Boolean.parseBoolean(includeProtocolBindingProp)) {
            authRequest.setProtocolBinding(SAMLConstants.SAML2_POST_BINDING_URI);
        }

        String acsUrl = null;
        AuthenticatorConfig authenticatorConfig =
                FileBasedConfigurationBuilder.getInstance().getAuthenticatorConfigMap()
                        .get(SSOConstants.AUTHENTICATOR_NAME);
        if (authenticatorConfig != null) {
            String tmpAcsUrl = authenticatorConfig.getParameterMap().get(SSOConstants.ServerConfig.SAML_SSO_ACS_URL);
            if (StringUtils.isNotBlank(tmpAcsUrl)) {
                acsUrl = tmpAcsUrl;
            }
        }

        if (acsUrl == null) {
            acsUrl = IdentityUtil.getServerURL(FrameworkConstants.COMMONAUTH, true, true);
        }

        authRequest.setAssertionConsumerServiceURL(acsUrl);
        authRequest.setIssuer(issuer);
        authRequest.setID(SSOUtils.createID());
        authRequest.setVersion(SAMLVersion.VERSION_20);
        authRequest.setDestination(idpUrl);

        String attributeConsumingServiceIndexProp = properties
                .get(IdentityApplicationConstants.Authenticator.SAML2SSO.ATTRIBUTE_CONSUMING_SERVICE_INDEX);
        if (StringUtils.isNotEmpty(attributeConsumingServiceIndexProp)) {
            try {
                authRequest.setAttributeConsumingServiceIndex(Integer
                        .valueOf(attributeConsumingServiceIndexProp));
            } catch (NumberFormatException e) {
                log.error(
                        "Error while populating SAMLRequest with AttributeConsumingServiceIndex: "
                                + attributeConsumingServiceIndexProp, e);
            }
        }

        String includeNameIDPolicyProp = properties
                .get(IdentityApplicationConstants.Authenticator.SAML2SSO.INCLUDE_NAME_ID_POLICY);
        if (StringUtils.isEmpty(includeNameIDPolicyProp) || Boolean.parseBoolean(includeNameIDPolicyProp)) {
            String nameIDType = properties.get(NAME_ID_TYPE);
            NameIDPolicyBuilder nameIdPolicyBuilder = new NameIDPolicyBuilder();
            NameIDPolicy nameIdPolicy = nameIdPolicyBuilder.buildObject();
            if (StringUtils.isNotBlank(nameIDType)) {
                nameIdPolicy.setFormat(nameIDType);
            } else {
                nameIdPolicy.setFormat(NameIDType.UNSPECIFIED);
            }
            if (spEntityId != null && !spEntityId.isEmpty()) {
                nameIdPolicy.setSPNameQualifier(spEntityId);
            }
            //nameIdPolicy.setSPNameQualifier(issuer);
            nameIdPolicy.setAllowCreate(true);
            authRequest.setNameIDPolicy(nameIdPolicy);
        }

        //Get the inbound SAMLRequest
        AuthnRequest inboundAuthnRequest = getAuthnRequest(context);

        RequestedAuthnContext requestedAuthnContext = buildRequestedAuthnContext(inboundAuthnRequest, request);
        if (requestedAuthnContext != null) {
            authRequest.setRequestedAuthnContext(requestedAuthnContext);
        }

        Extensions extensions = getSAMLExtensions(request);
        if (extensions != null) {
            authRequest.setExtensions(extensions);
        }

        return authRequest;
    }

    private RequestedAuthnContext buildRequestedAuthnContext(AuthnRequest inboundAuthnRequest,
                                                             HttpServletRequest request) throws SAMLSSOException {

        /* AuthnContext */
        RequestedAuthnContextBuilder requestedAuthnContextBuilder = null;
        RequestedAuthnContext requestedAuthnContext = null;

        String includeAuthnContext = properties
                .get(IdentityApplicationConstants.Authenticator.SAML2SSO.INCLUDE_AUTHN_CONTEXT);

        if (StringUtils.isNotEmpty(includeAuthnContext) && "as_request".equalsIgnoreCase(includeAuthnContext)) {
            if (inboundAuthnRequest != null) {

                RequestedAuthnContext incomingRequestedAuthnContext = inboundAuthnRequest.getRequestedAuthnContext();

                requestedAuthnContextBuilder = new RequestedAuthnContextBuilder();
                requestedAuthnContext = requestedAuthnContextBuilder.buildObject();
                if (incomingRequestedAuthnContext != null) {
                    requestedAuthnContext.getAuthnContextClassRefs();
                    requestedAuthnContext.setDOM(incomingRequestedAuthnContext.getDOM());
                } else {

                    String[] queryParamValues = null;
                    AuthenticatorConfig authenticatorConfig =
                            FileBasedConfigurationBuilder.getInstance().getAuthenticatorConfigMap()
                                    .get(SSOConstants.AUTHENTICATOR_NAME);
                    if (authenticatorConfig != null) {
                        String samlparamkey = authenticatorConfig.getParameterMap().get("SAMLSSOPARAMKey");
                        if (StringUtils.isNotBlank(samlparamkey)) {
                            String queryParam = request.getParameter(samlparamkey);
                            if (queryParam != null && !queryParam.isEmpty()) {
                                queryParamValues = queryParam.split(",");
                            }
                        }
                    }

                    if (queryParamValues != null) {
                        for (String queryParamValue : queryParamValues) {

                            AuthnContextClassRefBuilder authnContextClassRefBuilder = new AuthnContextClassRefBuilder();
                            AuthnContextClassRef authnContextClassRef = authnContextClassRefBuilder
                                    .buildObject(SAMLConstants.SAML20_NS,
                                            AuthnContextClassRef.DEFAULT_ELEMENT_LOCAL_NAME,
                                            SAMLConstants.SAML20_PREFIX);
                            String authnContextClass = queryParamValue;
                            String samlAuthnContextURN = IdentityApplicationManagementUtil
                                    .getSAMLAuthnContextClasses().get(authnContextClass);

                            if (!StringUtils.isBlank(samlAuthnContextURN)) {
                                //There was one matched URN for give authnContextClass.
                                authnContextClassRef.setAuthnContextClassRef(samlAuthnContextURN);

                            } else {
                                //There are no any matched URN for given authnContextClass, so added authnContextClass name to the
                                // AuthnContextClassRef.
                                authnContextClassRef.setAuthnContextClassRef(authnContextClass);
                            }

                            requestedAuthnContext.getAuthnContextClassRefs().add(authnContextClassRef);

                        }
                    } else {

                        AuthnContextClassRefBuilder authnContextClassRefBuilder = new AuthnContextClassRefBuilder();
                        AuthnContextClassRef authnContextClassRef = authnContextClassRefBuilder
                                .buildObject(SAMLConstants.SAML20_NS,
                                        AuthnContextClassRef.DEFAULT_ELEMENT_LOCAL_NAME,
                                        SAMLConstants.SAML20_PREFIX);
                        AuthnContextClassRef authnContextClassRef2 = authnContextClassRefBuilder
                                .buildObject(SAMLConstants.SAML20_NS,
                                        AuthnContextClassRef.DEFAULT_ELEMENT_LOCAL_NAME,
                                        SAMLConstants.SAML20_PREFIX);

                        if (authenticatorConfig != null) {
                            String authnContextClass =
                                    authenticatorConfig.getParameterMap().get("SAMLSSODefaultAuthnContext1");
                            String authContextClass2 =
                                    authenticatorConfig.getParameterMap().get("SAMLSSODefaultAuthnContext2");
                            if (StringUtils.isNotBlank(authnContextClass) &&
                                    StringUtils.isNotBlank(authContextClass2)) {

                                //There are no any matched URN for given authnContextClass, so added authnContextClass name to the
                                // AuthnContextClassRef.
                                authnContextClassRef.setAuthnContextClassRef(authnContextClass);
                                authnContextClassRef2.setAuthnContextClassRef(authContextClass2);
                                requestedAuthnContext.getAuthnContextClassRefs().add(authnContextClassRef);
                                requestedAuthnContext.getAuthnContextClassRefs().add(authnContextClassRef2);

                            }
                        }

                    }

                    /* Authentication Context Comparison Level */
                    String authnContextComparison =
                            IdentityApplicationConstants.Authenticator.SAML2SSO.AUTHENTICATION_CONTEXT_COMPARISON_LEVEL;
                    if (StringUtils.isNotEmpty(authnContextComparison)) {
                        if (AuthnContextComparisonTypeEnumeration.EXACT.toString().equalsIgnoreCase(
                                authnContextComparison)) {
                            requestedAuthnContext.setComparison(AuthnContextComparisonTypeEnumeration.EXACT);
                        } else if (AuthnContextComparisonTypeEnumeration.MINIMUM.toString().equalsIgnoreCase(
                                authnContextComparison)) {
                            requestedAuthnContext.setComparison(AuthnContextComparisonTypeEnumeration.MINIMUM);
                        } else if (AuthnContextComparisonTypeEnumeration.MAXIMUM.toString().equalsIgnoreCase(
                                authnContextComparison)) {
                            requestedAuthnContext.setComparison(AuthnContextComparisonTypeEnumeration.MAXIMUM);
                        } else if (AuthnContextComparisonTypeEnumeration.BETTER.toString().equalsIgnoreCase(
                                authnContextComparison)) {
                            requestedAuthnContext.setComparison(AuthnContextComparisonTypeEnumeration.BETTER);
                        }
                    } else {
                        requestedAuthnContext.setComparison(AuthnContextComparisonTypeEnumeration.EXACT);
                    }

                }
            }
        } else if (StringUtils.isEmpty(includeAuthnContext) || "yes".equalsIgnoreCase(includeAuthnContext)) {

            requestedAuthnContextBuilder = new RequestedAuthnContextBuilder();
            requestedAuthnContext = requestedAuthnContextBuilder.buildObject();
            /* AuthnContextClass */
            AuthnContextClassRefBuilder authnContextClassRefBuilder = new AuthnContextClassRefBuilder();
            AuthnContextClassRef authnContextClassRef = authnContextClassRefBuilder
                    .buildObject(SAMLConstants.SAML20_NS,
                            AuthnContextClassRef.DEFAULT_ELEMENT_LOCAL_NAME,
                            SAMLConstants.SAML20_PREFIX);

            String authnContextClass = properties
                    .get(IdentityApplicationConstants.Authenticator.SAML2SSO.AUTHENTICATION_CONTEXT_CLASS);

            if (StringUtils.isNotEmpty(authnContextClass)) {
                String samlAuthnContextURN = IdentityApplicationManagementUtil
                        .getSAMLAuthnContextClasses().get(authnContextClass);
                if (!StringUtils.isBlank(samlAuthnContextURN)) {
                    //There was one matched URN for give authnContextClass.
                    authnContextClassRef.setAuthnContextClassRef(samlAuthnContextURN);
                } else {
                    //There are no any matched URN for given authnContextClass, so added authnContextClass name to the
                    // AuthnContextClassRef.
                    authnContextClassRef.setAuthnContextClassRef(authnContextClass);
                }

            } else {
                authnContextClassRef.setAuthnContextClassRef(AuthnContext.PPT_AUTHN_CTX);
            }

            /* Authentication Context Comparison Level */
            String authnContextComparison = properties
                    .get(IdentityApplicationConstants.Authenticator.SAML2SSO.AUTHENTICATION_CONTEXT_COMPARISON_LEVEL);

            if (StringUtils.isNotEmpty(authnContextComparison)) {
                if (AuthnContextComparisonTypeEnumeration.EXACT.toString().equalsIgnoreCase(
                        authnContextComparison)) {
                    requestedAuthnContext.setComparison(AuthnContextComparisonTypeEnumeration.EXACT);
                } else if (AuthnContextComparisonTypeEnumeration.MINIMUM.toString().equalsIgnoreCase(
                        authnContextComparison)) {
                    requestedAuthnContext.setComparison(AuthnContextComparisonTypeEnumeration.MINIMUM);
                } else if (AuthnContextComparisonTypeEnumeration.MAXIMUM.toString().equalsIgnoreCase(
                        authnContextComparison)) {
                    requestedAuthnContext.setComparison(AuthnContextComparisonTypeEnumeration.MAXIMUM);
                } else if (AuthnContextComparisonTypeEnumeration.BETTER.toString().equalsIgnoreCase(
                        authnContextComparison)) {
                    requestedAuthnContext.setComparison(AuthnContextComparisonTypeEnumeration.BETTER);
                }
            } else {
                requestedAuthnContext.setComparison(AuthnContextComparisonTypeEnumeration.EXACT);
            }
            requestedAuthnContext.getAuthnContextClassRefs().add(authnContextClassRef);
        }
        return requestedAuthnContext;
    }

    private boolean isForceAuthenticate(AuthenticationContext context) {

        boolean forceAuthenticate = false;
        String forceAuthenticateProp = properties
                .get(IdentityApplicationConstants.Authenticator.SAML2SSO.FORCE_AUTHENTICATION);
        if ("yes".equalsIgnoreCase(forceAuthenticateProp)) {
            forceAuthenticate = true;
        } else if ("as_request".equalsIgnoreCase(forceAuthenticateProp)) {
            forceAuthenticate = context.isForceAuthenticate();
        }
        return forceAuthenticate;
    }

    private LogoutRequest buildLogoutRequest(String user, String sessionIndexStr, String idpUrl, String nameQualifier,
                                             String spNameQualifier)
            throws SAMLSSOException {

        LogoutRequest logoutReq = new LogoutRequestBuilder().buildObject();

        logoutReq.setID(SSOUtils.createID());
        logoutReq.setDestination(idpUrl);
        logoutReq.setDestination(idpUrl);

        DateTime issueInstant = new DateTime();
        logoutReq.setIssueInstant(issueInstant);
        logoutReq.setNotOnOrAfter(new DateTime(issueInstant.getMillis() + 5 * 60 * 1000));

        IssuerBuilder issuerBuilder = new IssuerBuilder();
        Issuer issuer = issuerBuilder.buildObject();

        String spEntityId = properties.get(IdentityApplicationConstants.Authenticator.SAML2SSO.SP_ENTITY_ID);

        if (spEntityId != null && !spEntityId.isEmpty()) {
            issuer.setValue(spEntityId);
        } else {
            issuer.setValue("carbonServer");
        }

        logoutReq.setIssuer(issuer);

        NameID nameId = new NameIDBuilder().buildObject();
        nameId.setFormat(NameIDType.UNSPECIFIED);
        nameId.setValue(user);
        nameId.setNameQualifier(nameQualifier);
        nameId.setSPNameQualifier(spNameQualifier);
        logoutReq.setNameID(nameId);

        SessionIndex sessionIndex = new SessionIndexBuilder().buildObject();

        if (sessionIndexStr != null) {
            sessionIndex.setSessionIndex(sessionIndexStr);
        } else {
            sessionIndex.setSessionIndex(UUID.randomUUID().toString());
        }

        logoutReq.getSessionIndexes().add(sessionIndex);
        logoutReq.setReason("Single Logout");

        return logoutReq;
    }

    private String encodeRequestMessage(RequestAbstractType requestMessage)
            throws SAMLSSOException {

        Marshaller marshaller = Configuration.getMarshallerFactory().getMarshaller(requestMessage);
        Element authDOM = null;
        try {
            authDOM = marshaller.marshall(requestMessage);

            /* Compress the message */
            Deflater deflater = new Deflater(Deflater.DEFLATED, true);
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            DeflaterOutputStream deflaterOutputStream = new DeflaterOutputStream(byteArrayOutputStream, deflater);
            StringWriter rspWrt = new StringWriter();
            XMLHelper.writeNode(authDOM, rspWrt);
            deflaterOutputStream.write(rspWrt.toString().getBytes());
            deflaterOutputStream.close();

            /* Encoding the compressed message */
            String encodedRequestMessage =
                    Base64.encodeBytes(byteArrayOutputStream.toByteArray(), Base64.DONT_BREAK_LINES);

            byteArrayOutputStream.write(byteArrayOutputStream.toByteArray());
            byteArrayOutputStream.toString();

            // log saml
            if (log.isDebugEnabled()) {
                log.debug("SAML Request  :  " + rspWrt.toString());
            }

            return URLEncoder.encode(encodedRequestMessage, "UTF-8").trim();

        } catch (MarshallingException | IOException e) {
            throw new SAMLSSOException("Error occurred while encoding SAML request", e);
        }
    }

}
