// Code generated by go-swagger; DO NOT EDIT.

package provider_accounts

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"

	strfmt "github.com/go-openapi/strfmt"

	models "github.com/propertechnologies/yodlee-go/models"
)

// UpdatePreferencesReader is a Reader for the UpdatePreferences structure.
type UpdatePreferencesReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *UpdatePreferencesReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 204:
		result := NewUpdatePreferencesNoContent()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewUpdatePreferencesBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewUpdatePreferencesUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewUpdatePreferencesNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	default:
		return nil, runtime.NewAPIError("unknown error", response, response.Code())
	}
}

// NewUpdatePreferencesNoContent creates a UpdatePreferencesNoContent with default headers values
func NewUpdatePreferencesNoContent() *UpdatePreferencesNoContent {
	return &UpdatePreferencesNoContent{}
}

/*UpdatePreferencesNoContent handles this case with default header values.

OK
*/
type UpdatePreferencesNoContent struct {
}

func (o *UpdatePreferencesNoContent) Error() string {
	return fmt.Sprintf("[PUT /providerAccounts/{providerAccountId}/preferences][%d] updatePreferencesNoContent ", 204)
}

func (o *UpdatePreferencesNoContent) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewUpdatePreferencesBadRequest creates a UpdatePreferencesBadRequest with default headers values
func NewUpdatePreferencesBadRequest() *UpdatePreferencesBadRequest {
	return &UpdatePreferencesBadRequest{}
}

/*UpdatePreferencesBadRequest handles this case with default header values.

Y800 : Invalid value for preferences<br>Y800 : Invalid value for preferences.isDataExtractsEnabled<br>Y800 : Invalid value for preferences.isAutoRefreshEnabled<br>Y807 : Resource not found<br>Y830 : Data extracts feature has to be enabled to set preferences.isDataExtractsEnabled as true<br>Y830 : Auto refresh feature has to be enabled to set preferences.isAutoRefreshEnabled as true
*/
type UpdatePreferencesBadRequest struct {
	Payload *models.YodleeError
}

func (o *UpdatePreferencesBadRequest) Error() string {
	return fmt.Sprintf("[PUT /providerAccounts/{providerAccountId}/preferences][%d] updatePreferencesBadRequest  %+v", 400, o.Payload)
}

func (o *UpdatePreferencesBadRequest) GetPayload() *models.YodleeError {
	return o.Payload
}

func (o *UpdatePreferencesBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.YodleeError)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdatePreferencesUnauthorized creates a UpdatePreferencesUnauthorized with default headers values
func NewUpdatePreferencesUnauthorized() *UpdatePreferencesUnauthorized {
	return &UpdatePreferencesUnauthorized{}
}

/*UpdatePreferencesUnauthorized handles this case with default header values.

Unauthorized
*/
type UpdatePreferencesUnauthorized struct {
}

func (o *UpdatePreferencesUnauthorized) Error() string {
	return fmt.Sprintf("[PUT /providerAccounts/{providerAccountId}/preferences][%d] updatePreferencesUnauthorized ", 401)
}

func (o *UpdatePreferencesUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewUpdatePreferencesNotFound creates a UpdatePreferencesNotFound with default headers values
func NewUpdatePreferencesNotFound() *UpdatePreferencesNotFound {
	return &UpdatePreferencesNotFound{}
}

/*UpdatePreferencesNotFound handles this case with default header values.

Not Found
*/
type UpdatePreferencesNotFound struct {
}

func (o *UpdatePreferencesNotFound) Error() string {
	return fmt.Sprintf("[PUT /providerAccounts/{providerAccountId}/preferences][%d] updatePreferencesNotFound ", 404)
}

func (o *UpdatePreferencesNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}
