// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	strfmt "github.com/go-openapi/strfmt"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/swag"
)

// TransactionCategorizationRuleRequest TransactionCategorizationRuleRequest
// swagger:model TransactionCategorizationRuleRequest
type TransactionCategorizationRuleRequest struct {

	// rule
	Rule *TransactionCategorizationRuleInfo `json:"rule,omitempty"`
}

// Validate validates this transaction categorization rule request
func (m *TransactionCategorizationRuleRequest) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateRule(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *TransactionCategorizationRuleRequest) validateRule(formats strfmt.Registry) error {

	if swag.IsZero(m.Rule) { // not required
		return nil
	}

	if m.Rule != nil {
		if err := m.Rule.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("rule")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *TransactionCategorizationRuleRequest) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *TransactionCategorizationRuleRequest) UnmarshalBinary(b []byte) error {
	var res TransactionCategorizationRuleRequest
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}