var round = Math.round;

function toggle(idButton, idDiv, label) {
	if(document.getElementById(idDiv)) {
		if(document.getElementById(idDiv).style.display == 'none') {
			document.getElementById(idDiv).style.display = 'block';
			document.getElementById(idButton).value = 'Hide '+label;
		} else {
			document.getElementById(idDiv).style.display = 'none';
			document.getElementById(idButton).value = 'Show '+label;
		}
	}
}

function dateTracker(obj, gtype, labels, datasets)
{
        var dateToDisplay = new Date(parseInt(obj.x));
        var posValue = parseInt(obj.x);

        // look for the position in data arrays 
        var pos = 0;
        if (datasets != undefined) {
                for (pos=0; pos < datasets[0].length; pos++) {
                        // If timestamp are the same we have found the position
                        if (datasets[0][pos][0] == posValue) {
                                // get out of here
                                break;
                        }
                }
        } else {
                return '<span class="mfigure">NO DATASET</span>';
        }

        var textToShow = '<div class="mouse-figures">';
        for (var i = 0; i < labels.length; i++) {
                if (datasets[i] != undefined) {
                        textToShow += '<span class="mfigure">'+pretty_print_number(datasets[i][pos][1], gtype)+' <small>'+labels[i]+'</small></span><br>';
                }
        }
        textToShow += '</div>';
        return textToShow;
}

function dateTracker2(obj, dtype, gtype) 
{
 	var dateToDisplay = obj.x;
	if (dtype == 'month') {
		var pos = parseInt(obj.x);
		dateToDisplay = months[(pos-1)%12];
	}
 	return dateToDisplay+', '+obj.series.label+': '+round(obj.y);
}
 
function pretty_print_number(val, type) 
{
 	if (type == 'size') {
 		if (val >= 1125899906842624) {
 			val = (val / 1125899906842624);
 			val = val.toFixed(2) + " PiB";
 		} else if (val >= 1099511627776) {
 			val = (val / 1099511627776);
 			val = val.toFixed(2) + " TiB";
 		} else if (val >= 1073741824) {
 			val = (val / 1073741824);
 			val = val.toFixed(2) + " GiB";
 		} else if (val >= 1048576) {
 			val = (val / 1048576);
 			val = val.toFixed(2) + " MiB";
 		} else if (val >= 1024) {
 			val = (val / 1024);
 			val = val.toFixed(2) + " KiB";
 		} else {
 			val = val + " B";
 		}
 	} else if (type == 'duration') {
 		if (val >= 1000) {
 			val = (val / 1000);
 			val = val.toFixed(3) + " sec";
 		} else {
 			val = val + " ms";
 		}
 	} else {
 		if (val >= 1000000000000000) {
 			val = (val / 1000000000000000);
 			val = val.toFixed(2) + " P";
 		} else if (val >= 1000000000000) {
 			val = (val / 1000000000000);
 			val = val.toFixed(2) + " T";
 		} else if (val >= 1000000000) {
 			val = (val / 1000000000);
 			val = val.toFixed(2) + " G";
 		} else if (val >= 1000000) {
 			val = (val / 1000000);
 			val = val.toFixed(2) + " M";
 		} else if (val >= 1000) {
 			val = (val / 1000);
 			val = val.toFixed(2) + " K";
 		}
 	}
 	return val;
}
 
function pieTracker(obj) 
{
 	return obj.series.label+': '+round(obj.y);
}

