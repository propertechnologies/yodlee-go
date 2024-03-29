// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"strconv"

	strfmt "github.com/go-openapi/strfmt"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/swag"
)

// DerivedTransactionSummaryResponse DerivedTransactionSummaryResponse
// swagger:model DerivedTransactionSummaryResponse
type DerivedTransactionSummaryResponse struct {

	// links
	// Read Only: true
	Links *DerivedTransactionsLinks `json:"links,omitempty"`

	// transaction summary
	// Read Only: true
	TransactionSummary []*DerivedTransactionsSummary `json:"transactionSummary"`
}

// Validate validates this derived transaction summary response
func (m *DerivedTransactionSummaryResponse) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateLinks(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateTransactionSummary(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *DerivedTransactionSummaryResponse) validateLinks(formats strfmt.Registry) error {

	if swag.IsZero(m.Links) { // not required
		return nil
	}

	if m.Links != nil {
		if err := m.Links.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("links")
			}
			return err
		}
	}

	return nil
}

func (m *DerivedTransactionSummaryResponse) validateTransactionSummary(formats strfmt.Registry) error {

	if swag.IsZero(m.TransactionSummary) { // not required
		return nil
	}

	for i := 0; i < len(m.TransactionSummary); i++ {
		if swag.IsZero(m.TransactionSummary[i]) { // not required
			continue
		}

		if m.TransactionSummary[i] != nil {
			if err := m.TransactionSummary[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("transactionSummary" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// MarshalBinary interface implementation
func (m *DerivedTransactionSummaryResponse) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *DerivedTransactionSummaryResponse) UnmarshalBinary(b []byte) error {
	var res DerivedTransactionSummaryResponse
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
