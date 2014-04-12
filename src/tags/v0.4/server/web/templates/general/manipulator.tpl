{# This is the little box on the left that follows you as you scroll. #}
{% load staticfiles %}
<script type="text/javascript" src="{% static 'js/manipulator.js' %}"></script>
<div id="manipulator" class="col-xs-2 col-sm-2 col-md-2">
	<div class="button-container well">
		<div class="btn-group-vertical btn-block">
			<button id="enable" type="button" class="btn btn-success btn-block">Enable{% csrf_token %}</button>
			<button id="disable" type="button" class="btn btn-danger btn-block">Disable{% csrf_token %}</button>
			<button id="filter" type="button" class="btn btn-warning btn-block" data-toggle="modal" data-target="#filterFormModal">Filter</button>
			<button id="suppress" type="button" class="btn btn-warning btn-block" data-toggle="modal" data-target="#suppressFormModal">Suppress</button>
			<button id="comment" type="button" class="btn btn-primary btn-block">Comment</button>
		</div>
		
	</div>
</div>

<div class="modal fade" id="filterFormModal" tabindex="-1" role="dialog" aria-labelledby="filterFormModal" aria-hidden="true">
  <div class="modal-dialog">
    <div class="modal-content">
      <div class="modal-header">
        <button type="button" class="close" data-dismiss="modal" aria-hidden="true">&times;</button>
        <h4 class="modal-title" id="filterFormModal">Set Threshold</h4>
      </div>
      <div class="modal-body">
        <form id="filterForm" class="form-horizontal" role="form">
        	<div id="formContent">
        
        	</div>
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-default" data-dismiss="modal">Close</button>
        <button type="submit" class="btn btn-primary" id="filter-submit" name="filter-submit">Save changes</button>
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

<div class="modal fade" id="modifyFormModal" tabindex="-1" role="dialog" aria-labelledby="modifyFormModal" aria-hidden="true">
  <div class="modal-dialog">
    <div class="modal-content">
      <div class="modal-header">
        <button type="button" class="close" data-dismiss="modal" aria-hidden="true">&times;</button>
        <h4 class="modal-title" id="modifyFormModal">Turn On/Off</h4>
      </div>
      <div class="modal-body">
        <form id="modifyForm" class="form-horizontal" role="form">
        	<div id="formContent">
        
        	</div>
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-default" data-dismiss="modal">Close</button>
        <button type="submit" class="btn btn-primary" id="modify-submit" name="modify-submit">Save changes</button>
        </form>
      </div>
    </div>
  </div>
</div>