import 'package:flutter/material.dart';
import 'package:video_player/video_player.dart';
import 'package:font_awesome_flutter/font_awesome_flutter.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:http/http.dart' as http;
import 'dart:convert';
import 'dart:async';

const String backendUrl = 'http://localhost:3000';

enum ElementType {
  heading, paragraph, button, list, video, card, icon, imageSlider, submitButton, nextButton, backButton, loginButton, image, logo, radioGroup, checkbox, bottomBar, cardRow2, cardRow3, appBar, inputField, uploadFile, userManagementTable
}

// Video Player Widget Implementation
class VideoPlayerWidget extends StatefulWidget {
  final String videoUrl;

  const VideoPlayerWidget({Key? key, required this.videoUrl}) : super(key: key);

  @override
  _VideoPlayerWidgetState createState() => _VideoPlayerWidgetState();
}
class _VideoPlayerWidgetState extends State<VideoPlayerWidget> {
  late VideoPlayerController _controller;
  bool _isInitialized = false;

  @override
  void initState() {
    super.initState();
    _initializeVideo();
  }

  void _initializeVideo() {
    _controller = VideoPlayerController.network(widget.videoUrl)
      ..initialize().then((_) {
        if (mounted) {
          setState(() {
            _isInitialized = true;
          });
          _controller.play();
          _controller.setLooping(true);
        }
      });
  }

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return AspectRatio(
      aspectRatio: _controller.value.aspectRatio,
      child: _isInitialized
          ? VideoPlayer(_controller)
          : const Center(child: CircularProgressIndicator()),
    );
  }
}
// Image Slider Widget Implementation
class ImageSliderWidget extends StatefulWidget {
  final List<String> imageUrls;
  final double height;

  const ImageSliderWidget({Key? key, required this.imageUrls, required this.height}) : super(key: key);

  @override
  _ImageSliderWidgetState createState() => _ImageSliderWidgetState();
}
class _ImageSliderWidgetState extends State<ImageSliderWidget> {
  final PageController _pageController = PageController();
  int _currentPage = 0;

  @override
  Widget build(BuildContext context) {
    return SizedBox(
      height: widget.height,
      child: Stack(
        children: [
          PageView.builder(
            controller: _pageController,
            itemCount: widget.imageUrls.length,
            onPageChanged: (index) {
              setState(() {
                _currentPage = index;
              });
            },
            itemBuilder: (context, index) {
              return Image.network(
                widget.imageUrls[index],
                fit: BoxFit.cover,
                errorBuilder: (context, error, stackTrace) =>
                  const Center(child: Text('Error loading image')),
              );
            },
          ),
          Positioned(
            bottom: 10,
            left: 0,
            right: 0,
            child: Row(
              mainAxisAlignment: MainAxisAlignment.center,
              children: List.generate(widget.imageUrls.length, (index) =>
                Container(
                  margin: const EdgeInsets.symmetric(horizontal: 4),
                  width: 8,
                  height: 8,
                  decoration: BoxDecoration(
                    shape: BoxShape.circle,
                    color: _currentPage == index ? Colors.white : Colors.white.withOpacity(0.5),
                  ),
                )
              ),
            ),
          ),
        ],
      ),
    );
  }
}


// Page Data
final Map<String, dynamic> pageData = {
  'name': 'Page 1',
  'backgroundColor': '#FFFFFF',
  'elements': [
    {
      'type': ElementType.heading,
      'elementId': '1758269995974',
      'text': 'New Heading',
      'color': '#000000',
      'size': 20,
      'padding': {
        'left': 8,
        'top': 8,
        'right': 8,
        'bottom': 8,
      },
      'margin': {
        'left': 4,
        'top': 4,
        'right': 4,
        'bottom': 4,
      },
      'width': double.infinity,
      'height': null,
      'listStyle': 'disc',
      'videoUrl': '',
      'imageUrls': [
      ],
      'icon': 'star',
      'bold': false,
      'italic': false,
      'underline': false,
      'backgroundColor': '#00000000',
      'borderRadius': 0,
      'borderWidth': 0,
      'borderColor': '#00000000',
      'alignment': 'left',
      'fontFamily': 'Poppins',
      'shadow': {
        'elevation': 0,
        'blurRadius': 0,
      },
      'opacity': 1,
      'textShadow': {
        'dx': 0,
        'dy': 0,
        'blurRadius': 0,
        'color': '#00000000',
      },
      'buttonStyle': null,
      'isSubmitButton': false,
      'fieldId': null,
      'fieldName': null,
      'inputType': 'text',
      'placeholder': 'Enter text',
      'borderStyle': 'solid',
      'imageStyle': 'rectangle',
      'backgroundImage': '',
      'horizontal': 'center',
      'vertical': 'center',
      'textWrapping': false,
      'imageInsideContent': false,
    },
    {
      'type': ElementType.paragraph,
      'elementId': '1758270088996',
      'text': 'New paragraph...',
      'color': '#000000',
      'size': 20,
      'padding': {
        'left': 8,
        'top': 8,
        'right': 8,
        'bottom': 8,
      },
      'margin': {
        'left': 4,
        'top': 4,
        'right': 4,
        'bottom': 4,
      },
      'width': double.infinity,
      'height': null,
      'listStyle': 'disc',
      'videoUrl': '',
      'imageUrls': [
      ],
      'icon': 'star',
      'bold': false,
      'italic': false,
      'underline': false,
      'backgroundColor': '#00000000',
      'borderRadius': 0,
      'borderWidth': 0,
      'borderColor': '#00000000',
      'alignment': 'left',
      'fontFamily': 'Poppins',
      'shadow': {
        'elevation': 0,
        'blurRadius': 0,
      },
      'opacity': 1,
      'textShadow': {
        'dx': 0,
        'dy': 0,
        'blurRadius': 0,
        'color': '#00000000',
      },
      'buttonStyle': null,
      'isSubmitButton': false,
      'fieldId': null,
      'fieldName': null,
      'inputType': 'text',
      'placeholder': 'Enter text',
      'borderStyle': 'solid',
      'imageStyle': 'rectangle',
      'backgroundImage': '',
      'horizontal': 'center',
      'vertical': 'center',
      'textWrapping': false,
      'imageInsideContent': false,
    },
    {
      'type': ElementType.button,
      'elementId': '1758270090615',
      'text': 'Click Me',
      'color': '#000000',
      'size': 20,
      'padding': {
        'left': 8,
        'top': 8,
        'right': 8,
        'bottom': 8,
      },
      'margin': {
        'left': 4,
        'top': 4,
        'right': 4,
        'bottom': 4,
      },
      'width': double.infinity,
      'height': null,
      'listStyle': 'disc',
      'videoUrl': '',
      'imageUrls': [
      ],
      'icon': 'star',
      'bold': false,
      'italic': false,
      'underline': false,
      'backgroundColor': '#00000000',
      'borderRadius': 0,
      'borderWidth': 0,
      'borderColor': '#00000000',
      'alignment': 'left',
      'fontFamily': 'Poppins',
      'shadow': {
        'elevation': 0,
        'blurRadius': 0,
      },
      'opacity': 1,
      'textShadow': {
        'dx': 0,
        'dy': 0,
        'blurRadius': 0,
        'color': '#00000000',
      },
      'buttonStyle': 'filled',
      'isSubmitButton': false,
      'fieldId': null,
      'fieldName': null,
      'inputType': 'text',
      'placeholder': 'Enter text',
      'borderStyle': 'solid',
      'imageStyle': 'rectangle',
      'backgroundImage': '',
      'horizontal': 'center',
      'vertical': 'center',
      'textWrapping': false,
      'imageInsideContent': false,
    },
  ]
};

class GeneratedPage extends StatefulWidget {
  const GeneratedPage({super.key});

  @override
  _GeneratedPageState createState() => _GeneratedPageState();
}

class _GeneratedPageState extends State<GeneratedPage> {
  final Map<String, TextEditingController> _controllers = {};
  bool _isSubmitting = false;

  @override
  void initState() {
    super.initState();
    _initControllers();
  }

  void _initControllers() {
    for (var el in pageData['elements']) {
      if (el['type'] == ElementType.inputField) {
        _controllers[el['fieldId']] = TextEditingController();
      }
    }
  }

  @override
  void dispose() {
    for (var controller in _controllers.values) {
      controller.dispose();
    }
    super.dispose();
  }

  Future<void> _submitForm() async {
    if (_isSubmitting) return;
    
    setState(() {
      _isSubmitting = true;
    });
    
    final Map<String, dynamic> formData = {};
    bool hasUsername = false;
    bool hasEmail = false;
    bool hasPassword = false;
    
    for (var el in pageData['elements']) {
      if (el['type'] == ElementType.inputField) {
        final fieldId = el['fieldId'] as String;
        final fieldName = el['fieldName'] as String?;
        final value = _controllers[fieldId]?.text ?? '';
        
        if (fieldName != null) {
          if (fieldName.toLowerCase().contains('name')) {
            formData['username'] = value;
            if (value.trim().isNotEmpty) hasUsername = true;
          } else if (fieldName.toLowerCase().contains('mail')) {
            formData['email'] = value;
            if (value.trim().isNotEmpty) hasEmail = true;
          } else if (fieldName.toLowerCase().contains('pass')) {
            formData['password'] = value;
            if (value.trim().isNotEmpty) hasPassword = true;
          } else {
            formData[fieldName] = value;
          }
        } else {
          formData[fieldId] = value;
        }
      }
    }
    
    if (!formData.containsKey('username')) formData['username'] = '';
    if (!formData.containsKey('email')) formData['email'] = '';
    if (!formData.containsKey('password')) formData['password'] = '';
    
    if (!hasUsername) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text("Please enter a username")),
      );
      setState(() { _isSubmitting = false; });
      return;
    }
    
    if (!hasEmail) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text("Please enter an email")),
      );
      setState(() { _isSubmitting = false; });
      return;
    }
    
    if (!hasPassword) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text("Please enter a password")),
      );
      setState(() { _isSubmitting = false; });
      return;
    }
    
    print("Submitting form to: " + backendUrl + "/submit-form");
    print("Form data: " + formData.toString());
    
    try {
      final response = await http.post(
        Uri.parse(backendUrl + "/submit-form"),
        headers: {'Content-Type': 'application/json'},
        body: jsonEncode(formData),
      ).timeout(const Duration(seconds: 30));
      
      print("Response status: " + response.statusCode.toString());
      print("Response body: " + response.body);
      
      if (response.statusCode == 200) {
        final result = jsonDecode(response.body);
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text("Form submitted successfully! ID: " + (result["id"] ?? "unknown").toString())),
        );
        _saveElementDataEdit(formData);
      } else {
        print("❌ Backend response: " + response.body);
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text("Failed: " + response.body)),
        );
      }
    } on TimeoutException catch (e) {
      print("❌ Form submission timed out: " + e.toString());
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text("Connection timed out. Please check your network connection.")),
      );
    } on http.ClientException catch (e) {
      print("❌ Client exception: " + e.toString());
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text("Unable to connect to server. Please check if the server is running.")),
      );
    } catch (e) {
      print("❌ Error submitting form: " + e.toString());
      ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text("Error: " + e.toString())),
      );
    } finally {
      setState(() {
        _isSubmitting = false;
      });
    }
  }

  Future<void> _saveElementDataEdit(Map<String, dynamic> formData) async {
    try {
      final response = await http.post(
        Uri.parse(backendUrl + "/save-element-data-edit"),
        headers: {'Content-Type': 'application/json'},
        body: jsonEncode({
          'elementData': formData,
          'inputFields': formData,
          'userId': null,
        }),
      ).timeout(const Duration(seconds: 30));
      
      if (response.statusCode == 200) {
        print('Element data saved successfully to user_edit_screen');
      } else {
        print('Failed to save element data: ${response.body}');
      }
    } catch (e) {
      print('Error saving element data: $e');
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: Container(
        color: Color(0xFFFFFF),
        child: ListView(
          children: [
            Padding(
            padding: EdgeInsets.fromLTRB(8, 8, 8, 8),
            child: Container(
              margin: EdgeInsets.fromLTRB(4, 4, 4, 4),
              width: double.infinity,
              decoration: BoxDecoration(
                color: Color(0x00000000),
                borderRadius: BorderRadius.circular(0),
              ),
              child: Opacity(
                opacity: 1,
                child: Text(
                  'New Heading',
                  style: GoogleFonts.getFont(
  'Poppins',
  fontSize: 20,
  color: Color(0x000000),
)
.copyWith(fontWeight: FontWeight.bold),
                  textAlign: TextAlign.left,
                ),
              ),
            ),
          ),

            Padding(
            padding: EdgeInsets.fromLTRB(8, 8, 8, 8),
            child: Container(
              margin: EdgeInsets.fromLTRB(4, 4, 4, 4),
              width: double.infinity,
              decoration: BoxDecoration(
                color: Color(0x00000000),
                borderRadius: BorderRadius.circular(0),
              ),
              child: Opacity(
                opacity: 1,
                child: Text(
                  'New paragraph...',
                  style: GoogleFonts.getFont(
  'Poppins',
  fontSize: 20,
  color: Color(0x000000),
)
,
                  textAlign: TextAlign.left,
                ),
              ),
            ),
          ),

            Padding(
            padding: EdgeInsets.fromLTRB(8, 8, 8, 8),
            child: Container(
              margin: EdgeInsets.fromLTRB(4, 4, 4, 4),
              width: double.infinity,
              decoration: BoxDecoration(
                color: Color(0x00000000),
                borderRadius: BorderRadius.circular(0),
              ),
              child: Opacity(
                opacity: 1,
                child: ElevatedButton(
                    onPressed: () {},
                    style: ElevatedButton.styleFrom(
                      minimumSize: Size(double.infinity, 50),
                      backgroundColor: Color(0x00000000),
                      foregroundColor: Color(0x000000),
                      shape: RoundedRectangleBorder(
                        borderRadius: BorderRadius.circular(0),
                      ),
                    ),
                    child: Text(
                      'Click Me',
                      style: GoogleFonts.getFont(
  'Poppins',
  fontSize: 20,
  color: Color(0x000000),
)
,
                    ),
                  ),
              ),
            ),
          ),

          ],
        ),
      ),
    );
  }
}

void main() {
  runApp(const MyApp());
}

class MyApp extends StatelessWidget {
  const MyApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Generated App',
      theme: ThemeData(
        primarySwatch: Colors.blue,
        useMaterial3: true,
      ),
      home: const GeneratedPage(),
    );
  }
}
