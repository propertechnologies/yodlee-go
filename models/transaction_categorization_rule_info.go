// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"encoding/json"
	"strconv"

	strfmt "github.com/go-openapi/strfmt"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/swag"
	"github.com/go-openapi/validate"
)

// TransactionCategorizationRuleInfo TransactionCategorizationRuleInfo
// swagger:model TransactionCategorizationRuleInfo
type TransactionCategorizationRuleInfo struct {

	// category Id
	CategoryID int32 `json:"categoryId,omitempty"`

	// priority
	Priority int32 `json:"priority,omitempty"`

	// rule clause
	RuleClause []*FieldOperation `json:"ruleClause"`

	// source
	// Enum: [SYSTEM USER]
	Source string `json:"source,omitempty"`
}

// Validate validates this transaction categorization rule info
func (m *TransactionCategorizationRuleInfo) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateRuleClause(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateSource(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *TransactionCategorizationRuleInfo) validateRuleClause(formats strfmt.Registry) error {

	if swag.IsZero(m.RuleClause) { // not required
		return nil
	}

	for i := 0; i < len(m.RuleClause); i++ {
		if swag.IsZero(m.RuleClause[i]) { // not required
			continue
		}

		if m.RuleClause[i] != nil {
			if err := m.RuleClause[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("ruleClause" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

var transactionCategorizationRuleInfoTypeSourcePropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["SYSTEM","USER"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		transactionCategorizationRuleInfoTypeSourcePropEnum = append(transactionCategorizationRuleInfoTypeSourcePropEnum, v)
	}
}

const (

	// TransactionCategorizationRuleInfoSourceSYSTEM captures enum value "SYSTEM"
	TransactionCategorizationRuleInfoSourceSYSTEM string = "SYSTEM"

	// TransactionCategorizationRuleInfoSourceUSER captures enum value "USER"
	TransactionCategorizationRuleInfoSourceUSER string = "USER"
)

// prop value enum
func (m *TransactionCategorizationRuleInfo) validateSourceEnum(path, location string, value string) error {
	if err := validate.Enum(path, location, value, transactionCategorizationRuleInfoTypeSourcePropEnum); err != nil {
		return err
	}
	return nil
}

func (m *TransactionCategorizationRuleInfo) validateSource(formats strfmt.Registry) error {

	if swag.IsZero(m.Source) { // not required
		return nil
	}

	// value enum
	if err := m.validateSourceEnum("source", "body", m.Source); err != nil {
		return err
	}

	return nil
}

// MarshalBinary interface implementation
func (m *TransactionCategorizationRuleInfo) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *TransactionCategorizationRuleInfo) UnmarshalBinary(b []byte) error {
	var res TransactionCategorizationRuleInfo
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}