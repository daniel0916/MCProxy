
cmake_minimum_required (VERSION 2.6)

project (MCProxy)

include_directories (SYSTEM "${PROJECT_SOURCE_DIR}/../lib/")
include_directories (SYSTEM "${PROJECT_SOURCE_DIR}/../lib/polarssl/include")

set(FOLDERS PolarSSL++)

if (NOT MSVC)
	
	foreach(folder ${FOLDERS})
		add_subdirectory(${folder})
	endforeach(folder)

	file(GLOB SOURCE
		"*.cpp"
		"*.h"
	)

else ()
	file(GLOB_RECURSE SOURCE
		"*.cpp"
		"*.h"
	)
	source_group("" FILES ${SOURCE})

	function(includefolder PATH)
		FILE(GLOB FOLDER_FILES
			"${PATH}/*.cpp"
			"${PATH}/*.h"
		)
		string(REPLACE "/" "\\" PROJECT_PATH ${PATH})
		source_group("${PROJECT_PATH}" FILES ${FOLDER_FILES})
	endfunction(includefolder)

	foreach(folder ${FOLDERS})
		includefolder(${folder})
	endforeach(folder)
endif()

set(EXECUTABLE MCProxy)
add_executable(${EXECUTABLE} ${SOURCE})

# Output the executable into the $/MCProxy folder, so that it has access to external resources:
set(EXECUTABLE_OUTPUT_PATH ${CMAKE_SOURCE_DIR}/MCProxy)
SET_TARGET_PROPERTIES(${EXECUTABLE} PROPERTIES
	RUNTIME_OUTPUT_DIRECTORY_DEBUG          ${CMAKE_SOURCE_DIR}/MCProxy
	RUNTIME_OUTPUT_DIRECTORY_RELEASE        ${CMAKE_SOURCE_DIR}/MCProxy
	RUNTIME_OUTPUT_DIRECTORY_DEBUGPROFILE   ${CMAKE_SOURCE_DIR}/MCProxy
	RUNTIME_OUTPUT_DIRECTORY_RELEASEPROFILE ${CMAKE_SOURCE_DIR}/MCProxy
)

if (NOT MSVC)
	target_link_libraries(${EXECUTABLE} PolarSSL++)
endif ()

target_link_libraries(${EXECUTABLE} zlib polarssl iniFile)
