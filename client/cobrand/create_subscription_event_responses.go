// Code generated by go-swagger; DO NOT EDIT.

package cobrand

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"

	strfmt "github.com/go-openapi/strfmt"

	models "github.com/propertechnologies/yodlee-go/models"
)

// CreateSubscriptionEventReader is a Reader for the CreateSubscriptionEvent structure.
type CreateSubscriptionEventReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *CreateSubscriptionEventReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 201:
		result := NewCreateSubscriptionEventCreated()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewCreateSubscriptionEventBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewCreateSubscriptionEventUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewCreateSubscriptionEventNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	default:
		return nil, runtime.NewAPIError("unknown error", response, response.Code())
	}
}

// NewCreateSubscriptionEventCreated creates a CreateSubscriptionEventCreated with default headers values
func NewCreateSubscriptionEventCreated() *CreateSubscriptionEventCreated {
	return &CreateSubscriptionEventCreated{}
}

/*CreateSubscriptionEventCreated handles this case with default header values.

OK
*/
type CreateSubscriptionEventCreated struct {
}

func (o *CreateSubscriptionEventCreated) Error() string {
	return fmt.Sprintf("[POST /cobrand/config/notifications/events/{eventName}][%d] createSubscriptionEventCreated ", 201)
}

func (o *CreateSubscriptionEventCreated) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewCreateSubscriptionEventBadRequest creates a CreateSubscriptionEventBadRequest with default headers values
func NewCreateSubscriptionEventBadRequest() *CreateSubscriptionEventBadRequest {
	return &CreateSubscriptionEventBadRequest{}
}

/*CreateSubscriptionEventBadRequest handles this case with default header values.

Y803 : eventName required<br>Y803 : callbackUrl required<br>Y800 : Invalid value for callbackUrl
*/
type CreateSubscriptionEventBadRequest struct {
	Payload *models.YodleeError
}

func (o *CreateSubscriptionEventBadRequest) Error() string {
	return fmt.Sprintf("[POST /cobrand/config/notifications/events/{eventName}][%d] createSubscriptionEventBadRequest  %+v", 400, o.Payload)
}

func (o *CreateSubscriptionEventBadRequest) GetPayload() *models.YodleeError {
	return o.Payload
}

func (o *CreateSubscriptionEventBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.YodleeError)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateSubscriptionEventUnauthorized creates a CreateSubscriptionEventUnauthorized with default headers values
func NewCreateSubscriptionEventUnauthorized() *CreateSubscriptionEventUnauthorized {
	return &CreateSubscriptionEventUnauthorized{}
}

/*CreateSubscriptionEventUnauthorized handles this case with default header values.

Unauthorized
*/
type CreateSubscriptionEventUnauthorized struct {
}

func (o *CreateSubscriptionEventUnauthorized) Error() string {
	return fmt.Sprintf("[POST /cobrand/config/notifications/events/{eventName}][%d] createSubscriptionEventUnauthorized ", 401)
}

func (o *CreateSubscriptionEventUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewCreateSubscriptionEventNotFound creates a CreateSubscriptionEventNotFound with default headers values
func NewCreateSubscriptionEventNotFound() *CreateSubscriptionEventNotFound {
	return &CreateSubscriptionEventNotFound{}
}

/*CreateSubscriptionEventNotFound handles this case with default header values.

Not Found
*/
type CreateSubscriptionEventNotFound struct {
}

func (o *CreateSubscriptionEventNotFound) Error() string {
	return fmt.Sprintf("[POST /cobrand/config/notifications/events/{eventName}][%d] createSubscriptionEventNotFound ", 404)
}

func (o *CreateSubscriptionEventNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}
