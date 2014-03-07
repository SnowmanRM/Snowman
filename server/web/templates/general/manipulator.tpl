{# This is the little box on the left that follows you as you scroll. #}
{% load staticfiles %}
<script type="text/javascript" src="{% static 'js/manipulator.js' %}"></script>
<div id="manipulator" class="col-xs-2 col-sm-2 col-md-2">
	<div class="button-container well">
		<div class="btn-group-vertical btn-block">
			<button id="enable" type="button" class="btn btn-success btn-block">Enable</button>
			<button id="disable" type="button" class="btn btn-danger btn-block">Disable</button>
			<button id="threshold" type="button" class="btn btn-warning btn-block" data-toggle="modal" data-target="#thresholdFormModal">Threshold</button>
			<button id="suppress" type="button" class="btn btn-warning btn-block" data-toggle="modal" data-target="#suppressFormModal">Suppress</button>
			<button id="comment" type="button" class="btn btn-primary btn-block">Comment</button>
		</div>
		<button id="" type="button" class="btn btn-primary btn-block">Commit changes</button>
	</div>
</div>

<div class="modal fade" id="thresholdFormModal" tabindex="-1" role="dialog" aria-labelledby="thresholdFormModal" aria-hidden="true">
  <div class="modal-dialog">
    <div class="modal-content">
      <div class="modal-header">
        <button type="button" class="close" data-dismiss="modal" aria-hidden="true">&times;</button>
        <h4 class="modal-title" id="thresholdFormModal">Set Threshold</h4>
      </div>
      <div class="modal-body">
        <form id="thresholdForm" class="form-horizontal" role="form">
        	<div id="formContent">
        
        	</div>
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-default" data-dismiss="modal">Close</button>
        <button type="submit" class="btn btn-primary" id="threshold-submit" name="threshold-submit">Save changes</button>
        </form>
      </div>
    </div>
  </div>
</div>

<div class="modal fade" id="suppressFormModal" tabindex="-1" role="dialog" aria-labelledby="suppressFormModal" aria-hidden="true">
  <div class="modal-dialog">
    <div class="modal-content">
      <div class="modal-header">
        <button type="button" class="close" data-dismiss="modal" aria-hidden="true">&times;</button>
        <h4 class="modal-title" id="suppressFormModal">Set Suppression</h4>
      </div>
      <div class="modal-body">
        <form id="suppressForm" class="form-horizontal" role="form">
        	<div id="formContent">
        
        	</div>
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-default" data-dismiss="modal">Close</button>
        <button type="submit" class="btn btn-primary" id="suppress-submit" name="suppress-submit">Save changes</button>
        </form>
      </div>
    </div>
  </div>
</div>