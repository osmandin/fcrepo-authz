/**
 * Copyright 2013 DuraSpace, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.fcrepo.auth.xacml;

import javax.xml.bind.JAXBElement;

import org.jboss.security.xacml.core.model.policy.ActionMatchType;
import org.jboss.security.xacml.core.model.policy.ActionType;
import org.jboss.security.xacml.core.model.policy.ActionsType;
import org.jboss.security.xacml.core.model.policy.ApplyType;
import org.jboss.security.xacml.core.model.policy.AttributeValueType;
import org.jboss.security.xacml.core.model.policy.ConditionType;
import org.jboss.security.xacml.core.model.policy.EffectType;
import org.jboss.security.xacml.core.model.policy.ExpressionType;
import org.jboss.security.xacml.core.model.policy.FunctionType;
import org.jboss.security.xacml.core.model.policy.ObjectFactory;
import org.jboss.security.xacml.core.model.policy.PolicyType;
import org.jboss.security.xacml.core.model.policy.RuleType;
import org.jboss.security.xacml.core.model.policy.SubjectAttributeDesignatorType;
import org.jboss.security.xacml.core.model.policy.TargetType;
import org.jboss.security.xacml.factories.PolicyAttributeFactory;
import org.jboss.security.xacml.interfaces.XACMLConstants;
import org.jboss.security.xacml.interfaces.XMLSchemaConstants;

/**
 * @author Gregory Jansen
 */
public class BasicJavaPolicyFactory {

    /**
     * @return
     */
    public static PolicyType constructReaderPolicy() {
        final ObjectFactory objectFactory = new ObjectFactory();

        final String PERMIT_OVERRIDES =
                "urn:oasis:names:tc:xacml:1.0:rule-combining-algorithm:permit-overrides";
        final PolicyType policyType = new PolicyType();
        policyType.setPolicyId("ReaderPolicy");
        policyType.setVersion("2.0");
        policyType.setRuleCombiningAlgId(PERMIT_OVERRIDES);

        // Create a target
        final TargetType targetType = new TargetType();

        // final ResourcesType resourcesType = new ResourcesType();
        // final ResourceType resourceType = new ResourceType();
        // final ResourceMatchType rmt = new ResourceMatchType();
        // rmt.setMatchId(XACMLConstants.FUNCTION_ANYURI_EQUAL);
        // rmt.setResourceAttributeDesignator(PolicyAttributeFactory
        // .createAttributeDesignatorType(
        // XACMLConstants.ATTRIBUTEID_RESOURCE_ID,
        // XMLSchemaConstants.DATATYPE_ANYURI));
        // rmt.setAttributeValue(PolicyAttributeFactory
        // .createAnyURIAttributeType(new URI(
        // "http://test/developer-guide.html")));
        // resourceType.getResourceMatch().add(rmt);
        // resourcesType.getResource().add(resourceType);
        //
        // targetType.setResources(resourcesType);

        policyType.setTarget(targetType);

        // Create a Rule
        final RuleType permitRule = new RuleType();
        permitRule.setRuleId("ReaderRule");
        permitRule.setEffect(EffectType.PERMIT);

        final ActionsType permitRuleActionsType = new ActionsType();
        final ActionType permitRuleActionType = new ActionType();

        final ActionMatchType amct = new ActionMatchType();
        amct.setMatchId("urn:oasis:names:tc:xacml:1.0:function:string-equal");
        amct.setAttributeValue(PolicyAttributeFactory
                .createStringAttributeType("read"));
        amct.setActionAttributeDesignator(PolicyAttributeFactory
                .createAttributeDesignatorType(
                        XACMLConstants.ATTRIBUTEID_ACTION_ID,
                        XMLSchemaConstants.DATATYPE_STRING, null, true));
        permitRuleActionType.getActionMatch().add(amct);
        final TargetType permitRuleTargetType = new TargetType();
        permitRuleActionsType.getAction().add(permitRuleActionType);
        permitRuleTargetType.setActions(permitRuleActionsType);
        permitRule.setTarget(permitRuleTargetType);

        final ConditionType permitRuleConditionType = new ConditionType();
        final FunctionType functionType = new FunctionType();
        functionType.setFunctionId(XACMLConstants.FUNCTION_STRING_EQUAL);
        final JAXBElement<ExpressionType> jaxbElementFunctionType =
                objectFactory.createExpression(functionType);
        permitRuleConditionType.setExpression(jaxbElementFunctionType);

        final ApplyType permitRuleApplyType = new ApplyType();
        permitRuleApplyType.setFunctionId(XACMLConstants.FUNCTION_STRING_IS_IN);

        final SubjectAttributeDesignatorType sadt =
                PolicyAttributeFactory.createSubjectAttributeDesignatorType(
                        XACMLConstants.ATTRIBUTEID_ROLE,
                        XMLSchemaConstants.DATATYPE_STRING, null, false,
                        null);
        final JAXBElement<SubjectAttributeDesignatorType> sadtElement =
                objectFactory.createSubjectAttributeDesignator(sadt);
        final AttributeValueType avt =
                PolicyAttributeFactory.createStringAttributeType("reader");
        final JAXBElement<AttributeValueType> jaxbAVT =
                objectFactory.createAttributeValue(avt);
        permitRuleApplyType.getExpression().add(jaxbAVT);
        permitRuleApplyType.getExpression().add(sadtElement);

        permitRuleConditionType.setExpression(objectFactory
                .createApply(permitRuleApplyType));

        permitRule.setCondition(permitRuleConditionType);

        policyType
                .getCombinerParametersOrRuleCombinerParametersOrVariableDefinition()
                .add(permitRule);

        // Create a Deny Rule
        final RuleType denyRule = new RuleType();
        denyRule.setRuleId("DenyRule");
        denyRule.setEffect(EffectType.DENY);
        policyType
                .getCombinerParametersOrRuleCombinerParametersOrVariableDefinition()
                .add(denyRule);

        return policyType;
    }
}
