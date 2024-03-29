// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"encoding/json"

	strfmt "github.com/go-openapi/strfmt"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/swag"
	"github.com/go-openapi/validate"
)

// UpdateCategoryRequest UpdateCategoryRequest
// swagger:model UpdateCategoryRequest
type UpdateCategoryRequest struct {

	// category name
	CategoryName string `json:"categoryName,omitempty"`

	// high level category name
	HighLevelCategoryName string `json:"highLevelCategoryName,omitempty"`

	// id
	ID int64 `json:"id,omitempty"`

	// source
	// Enum: [SYSTEM USER]
	Source string `json:"source,omitempty"`
}

// Validate validates this update category request
func (m *UpdateCategoryRequest) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateSource(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

var updateCategoryRequestTypeSourcePropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["SYSTEM","USER"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		updateCategoryRequestTypeSourcePropEnum = append(updateCategoryRequestTypeSourcePropEnum, v)
	}
}

const (

	// UpdateCategoryRequestSourceSYSTEM captures enum value "SYSTEM"
	UpdateCategoryRequestSourceSYSTEM string = "SYSTEM"

	// UpdateCategoryRequestSourceUSER captures enum value "USER"
	UpdateCategoryRequestSourceUSER string = "USER"
)

// prop value enum
func (m *UpdateCategoryRequest) validateSourceEnum(path, location string, value string) error {
	if err := validate.Enum(path, location, value, updateCategoryRequestTypeSourcePropEnum); err != nil {
		return err
	}
	return nil
}

func (m *UpdateCategoryRequest) validateSource(formats strfmt.Registry) error {

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
func (m *UpdateCategoryRequest) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *UpdateCategoryRequest) UnmarshalBinary(b []byte) error {
	var res UpdateCategoryRequest
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
