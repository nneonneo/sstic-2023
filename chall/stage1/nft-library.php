R%<?php
header("X-Powered-By: ImageMagick/7.1.0-51");

// SSTIC{8c44f9aa39f4f69d26b91ae2b49ed4d2d029c0999e691f3122a883b01ee19fae}
// Une sauvegarde de l'infrastructure est disponible dans les fichiers suivants
// /backup.tgz, /devices.tgz
//




if (!empty($_GET['id'])) {
    $image_id = $_GET['id'];
    if (!preg_match('/^[0-9]+$/', $image_id)) {
        die('Invalid ID');
    }
    $image_id = (int)$image_id;
    if (file_exists("images/$image_id.png")) {
        header('Content-Type: image/svg+xml');
        $imageData = file_get_contents("images/$image_id.png");
        $base64_image = base64_encode($imageData);
        echo '<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" viewBox="0 0 128 128"> <image width="100" height="100" x="14" y="10" xlink:href="data:image/png;base64,'.$base64_image.'"/> </svg>';
        exit;
    }
    else {
        header('Content-Type: image/svg+xml');
        echo '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 256 100"><text fill="blue" x="128" y="50" text-anchor="middle" dominant-baseline="middle" font-size="15">Placeholder ' . $image_id . '</text></svg>';
        exit;
    }   
}

if (!empty($_POST['filedata'])) {
    // The data needs to start with a valid PNG header, encoded in base64
    $filedata = $_POST['filedata'];
    if (!str_starts_with($filedata, "iVBORw0KGgoAAAANSUhEUg")) {
        die('Invalid image header');
    }
    $data = base64_decode($_POST['filedata']);

    $descriptorspec = array(
       0 => array("pipe", "r"),
       1 => array("pipe", "w"),
       2 => array("pipe", "w"),
    );

    // Convert the image to the right size
    $process = proc_open("convert png:- -resize 256x256 png:-", $descriptorspec, $pipes, '.', array());
    if (!is_resource($process)) {
        die('Internal Server Error with proc_open');
    }
    fwrite($pipes[0], $data);
    fclose($pipes[0]);

    header('Content-Type: image/png');
    echo stream_get_contents($pipes[1]);
    fclose($pipes[1]);
    fclose($pipes[2]);
    proc_close($process);
    exit;
}
?>
<!doctype html>
<html lang="en">
    <head>
        <title>Create your own NFT gallery!</title>
        <meta charset="utf-8">
        <style>
            body {
                text-align: center;
            }
            #drag-area {
                margin: 1em 20%;
                padding: 100px 20px;
                text-align: center;
                font-size: 1.25em;
                background-color: white;
                border: 2px dashed #ccc;
                border-radius: 25px;
            }

            #drag-area.is-dragover {
                background-color: white;
                border: 2px solid #bbb;
                color: gray;
            }
        </style>
        <script>
"use strict";

function setup_drag_and_drop_area(dnd_div) {
    const has_dnd_upload = (
        (('draggable' in dnd_div) || ('ondragstart' in dnd_div && 'ondrop' in dnd_div)) &&
        'FormData' in window &&
        'FileReader' in window);
    if (!has_dnd_upload) {
        // Hide the Drag-and-Drop feature
        dnd_div.style.display = 'none';
        return;
    }
    ['drag', 'dragend', 'dragenter', 'dragleave', 'dragover', 'dragstart', 'drop'].forEach(function(event_name) {
        dnd_div.addEventListener(event_name, function(e) {
            e.preventDefault();
            e.stopPropagation();
        });
    });
    ['dragover', 'dragenter'].forEach(function(event_name) {
        dnd_div.addEventListener(event_name, function(e) {
            dnd_div.classList.add('is-dragover');
        });
    });
    ['dragleave', 'dragend', 'drop'].forEach(function(event_name) {
        dnd_div.addEventListener(event_name, function(e) {
           dnd_div.classList.remove('is-dragover');
        });
    });
    dnd_div.addEventListener('drop', function(e) {
        upload_the_file(e.dataTransfer.files[0]);
    });
}
window.onload = function() {
    setup_drag_and_drop_area(document.getElementById('drag-area'));
};

function upload_the_file(file) {
    // Show the loaded file in JavaScript console
    console.log(file);

    const reader = new FileReader();
    reader.addEventListener('load', function(e) {
        const data = e.target.result;
        console.log("File loaded (" + data.byteLength + " bytes)");

        const binary = Array.prototype.map.call(new Uint8Array(data), function(x) {
            return String.fromCharCode(x);
        });
        document.getElementById("filedata").value = window.btoa(binary.join(''));
        document.getElementById("form").submit();
    });
    reader.readAsArrayBuffer(file);
}
        </script>
    </head>
    <body>
        <h1>Create your own NFT gallery!</h1>
        <p>Before creating your gallery, your image needs to be of the right size. Use this service to resize it!</p>
        <form id="form" action="<?php echo $_SERVER['PHP_SELF']; ?>" method="POST">
            <label for="file">Browse your filesystem:</label>
            <input type="file" onchange="upload_the_file(this.files[0]);">
            <input type="hidden" name="filedata" id="filedata" value="">
            <div id="drag-area">... or drop a file here.</div>
        </form>
    </body>
</html>
