/*
Copyright 2024 Preferred Networks, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package kaptest

import (
	"context"
	"fmt"
	"reflect"

	v1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/admission"
	"k8s.io/apiserver/pkg/admission/plugin/cel"
	"k8s.io/apiserver/pkg/admission/plugin/policy/validating"
	"k8s.io/apiserver/pkg/admission/plugin/webhook/matchconditions"
	celconfig "k8s.io/apiserver/pkg/apis/cel"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/cel/environment"
)

// ValidatorInterface is an interface to evaluate ValidatingAdmissionPolicy.
type ValidatorInterface interface {
	EvalMatchCondition(p ValidationParams) matchconditions.MatchResult
	Validate(p ValidationParams) validating.ValidateResult
}

type Validator struct {
	policy    *v1.ValidatingAdmissionPolicy
	validator validating.Validator
	matcher   matchconditions.Matcher
}

var _ ValidatorInterface = &Validator{}

// ValidationParams contains the parameters required to evaluate a ValidatingAdmissionPolicy.
type ValidationParams struct {
	Object       runtime.Object
	OldObject    runtime.Object
	ParamObj     runtime.Object
	NamespaceObj *corev1.Namespace
	UserInfo     user.Info
}

func (p ValidationParams) Operation() admission.Operation {
	if p.Object != nil && p.OldObject != nil {
		return admission.Update
	}
	if p.Object != nil {
		return admission.Create
	}
	return admission.Delete
}

// NewValidator compiles the provided ValidatingAdmissionPolicy and generates Validator.
func NewValidator(policy *v1.ValidatingAdmissionPolicy) *Validator {
	v, m := compilePolicy(policy)
	return &Validator{validator: v, policy: policy, matcher: m}
}

// Original: https://github.com/kubernetes/apiserver/blob/v0.32.1/pkg/admission/plugin/policy/validating/plugin.go
func compilePolicy(policy *v1.ValidatingAdmissionPolicy) (validating.Validator, matchconditions.Matcher) {
	hasParam := false
	if policy.Spec.ParamKind != nil {
		hasParam = true
	}
	/*
		strictCost := utilfeature.DefaultFeatureGate.Enabled(features.StrictCostEnforcementForVAP)
	*/
	strictCost := false
	optionalVars := cel.OptionalVariableDeclarations{HasParams: hasParam, HasAuthorizer: true, StrictCost: strictCost}
	expressionOptionalVars := cel.OptionalVariableDeclarations{HasParams: hasParam, HasAuthorizer: false, StrictCost: strictCost}
	failurePolicy := policy.Spec.FailurePolicy
	var matcher matchconditions.Matcher = nil
	matchConditions := policy.Spec.MatchConditions
	var compositionEnvTemplate *cel.CompositionEnv
	/*
		if strictCost {
			compositionEnvTemplate = getCompositionEnvTemplateWithStrictCost()
		} else {
			compositionEnvTemplate = getCompositionEnvTemplateWithoutStrictCost()
		}
	*/
	// https://github.com/kubernetes/apiserver/blob/v0.32.1/pkg/admission/plugin/policy/validating/plugin.go#L67
	compositionEnvTemplate, err := cel.NewCompositionEnv(cel.VariablesTypeName, environment.MustBaseEnvSet(environment.DefaultCompatibilityVersion(), false))
	if err != nil {
		panic(err)
	}

	filterCompiler := cel.NewCompositedCompilerFromTemplate(compositionEnvTemplate)
	filterCompiler.CompileAndStoreVariables(convertv1beta1Variables(policy.Spec.Variables), optionalVars, environment.StoredExpressions)

	if len(matchConditions) > 0 {
		matchExpressionAccessors := make([]cel.ExpressionAccessor, len(matchConditions))
		for i := range matchConditions {
			matchExpressionAccessors[i] = (*matchconditions.MatchCondition)(&matchConditions[i])
		}
		matcher = matchconditions.NewMatcher(filterCompiler.CompileCondition(matchExpressionAccessors, optionalVars, environment.StoredExpressions), failurePolicy, "policy", "validate", policy.Name)
	}
	res := validating.NewValidator(
		filterCompiler.CompileCondition(convertv1Validations(policy.Spec.Validations), optionalVars, environment.StoredExpressions),
		matcher,
		filterCompiler.CompileCondition(convertv1AuditAnnotations(policy.Spec.AuditAnnotations), optionalVars, environment.StoredExpressions),
		filterCompiler.CompileCondition(convertv1MessageExpressions(policy.Spec.Validations), expressionOptionalVars, environment.StoredExpressions),
		failurePolicy,
	)

	return res, matcher
}

func convertv1Validations(inputValidations []v1.Validation) []cel.ExpressionAccessor {
	celExpressionAccessor := make([]cel.ExpressionAccessor, len(inputValidations))
	for i, validation := range inputValidations {
		validation := validating.ValidationCondition{
			Expression: validation.Expression,
			Message:    validation.Message,
			Reason:     validation.Reason,
		}
		celExpressionAccessor[i] = &validation
	}
	return celExpressionAccessor
}

func convertv1MessageExpressions(inputValidations []v1.Validation) []cel.ExpressionAccessor {
	celExpressionAccessor := make([]cel.ExpressionAccessor, len(inputValidations))
	for i, validation := range inputValidations {
		if validation.MessageExpression != "" {
			condition := validating.MessageExpressionCondition{
				MessageExpression: validation.MessageExpression,
			}
			celExpressionAccessor[i] = &condition
		}
	}
	return celExpressionAccessor
}

func convertv1AuditAnnotations(inputValidations []v1.AuditAnnotation) []cel.ExpressionAccessor {
	celExpressionAccessor := make([]cel.ExpressionAccessor, len(inputValidations))
	for i, validation := range inputValidations {
		validation := validating.AuditAnnotationCondition{
			Key:             validation.Key,
			ValueExpression: validation.ValueExpression,
		}
		celExpressionAccessor[i] = &validation
	}
	return celExpressionAccessor
}

func convertv1beta1Variables(variables []v1.Variable) []cel.NamedExpressionAccessor {
	namedExpressions := make([]cel.NamedExpressionAccessor, len(variables))
	for i, variable := range variables {
		namedExpressions[i] = &validating.Variable{Name: variable.Name, Expression: variable.Expression}
	}
	return namedExpressions
}

// EvalMatchCondition evaluates ValidatingAdmissionPolicies' match conditions.
// It returns the result of the matchCondition evaluation to tell the caller which one is evaluated as 'false'.
// This is a hack to be able to check the name of failed expressions in matchCondition.
//
// TODO: Remove this func after k/k's Validate func outputs the name of the failed matchCondition.
func (v *Validator) EvalMatchCondition(p ValidationParams) matchconditions.MatchResult {
	if v.matcher == nil {
		panic("matcher is not defined")
	}
	ctx := context.Background()
	versionedAttribute, _ := makeVersionedAttribute(p)
	return v.matcher.Match(ctx, versionedAttribute, p.ParamObj, stubAuthz())
}

// Validate evaluates ValidationAdmissionPolicies' validations.
// ValidationResult contains the result of each validation(Admit, Deny, Error)
// and the reason if it is evaluated as Deny or Error.
func (v *Validator) Validate(p ValidationParams) validating.ValidateResult {
	ctx := context.Background()
	versionedAttribute, matchedResource := makeVersionedAttribute(p)

	return v.validator.Validate(
		ctx,
		matchedResource,
		versionedAttribute,
		p.ParamObj,
		p.NamespaceObj,
		celconfig.RuntimeCELCostBudget,
		// Inject stub authorizer since this testing tool focuses on the validation logic.
		stubAuthz(),
	)
}

func makeVersionedAttribute(p ValidationParams) (*admission.VersionedAttributes, schema.GroupVersionResource) {
	nameWithGVK, err := getNameWithGVK(p)
	if err != nil {
		return nil, schema.GroupVersionResource{}
	}
	groupVersionResource := schema.GroupVersionResource{
		Group:   nameWithGVK.gvk.Group,
		Version: nameWithGVK.gvk.Version,
		// NOTE: GVR.Resource is not populated
		Resource: "",
	}
	return &admission.VersionedAttributes{
		Attributes: admission.NewAttributesRecord(
			p.Object,
			p.OldObject,
			nameWithGVK.gvk,
			nameWithGVK.namespace,
			nameWithGVK.name,
			groupVersionResource,
			// NOTE: subResource is not populated
			"", // subResource
			p.Operation(),
			// NOTE: operationOptions is not populated
			nil, // operationOptions
			// NOTE: dryRun is always true
			true, // dryRun
			p.UserInfo,
		),
		VersionedOldObject: p.OldObject,
		VersionedObject:    p.Object,
		VersionedKind:      nameWithGVK.gvk,
		Dirty:              false,
	}, groupVersionResource
}

type nameWithGVK struct {
	namespace string
	name      string
	gvk       schema.GroupVersionKind
}

func getNameWithGVK(p ValidationParams) (*nameWithGVK, error) {
	if isNil(p.Object) && isNil(p.OldObject) {
		return nil, fmt.Errorf("object or oldObject must be set")
	}

	obj := p.Object
	if isNil(obj) {
		obj = p.OldObject
	}

	namer := meta.NewAccessor()
	name, err := namer.Name(obj)
	if err != nil {
		return nil, fmt.Errorf("name is not valid: %w", err)
	}

	namespaceName, err := namer.Namespace(obj)
	if err != nil {
		return nil, fmt.Errorf("namespace is not valid: %w", err)
	}

	gvk := obj.GetObjectKind().GroupVersionKind()

	return &nameWithGVK{
		name:      name,
		namespace: namespaceName,
		gvk:       gvk,
	}, nil
}

func isNil(obj runtime.Object) bool {
	return obj == nil || reflect.ValueOf(obj).IsNil()
}
